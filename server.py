import re
import time
import asyncio
import aiodns
import aiohttp
import validators
import socket

from sanic import Sanic
from sanic.log import logger
from sanic.response import html, json as json_response
from sanic.exceptions import InvalidUsage

app = Sanic()

# keep that in memory
RATE_LIMIT_DB = {}

# to prevent DDoS or bounce attack attempt or something like that
RATE_LIMIT_SECONDS = 5


def clear_rate_limit_db(now):
    to_delete = []

    "Remove too old rate limit values"
    for key, value in RATE_LIMIT_DB.items():
        if now - value > RATE_LIMIT_SECONDS:
            # a dictionnary can't be modified during iteration so delegate this
            # operation
            to_delete.append(key)

    for key in to_delete:
        del RATE_LIMIT_DB[key]


def check_rate_limit(key, now):

    if key in RATE_LIMIT_DB:
        since_last_attempt = now - RATE_LIMIT_DB[key]
        if since_last_attempt < RATE_LIMIT_SECONDS:
            logger.info(f"Rate limit reached for {key}, can retry in {int(RATE_LIMIT_SECONDS - since_last_attempt)} seconds")
            return json_response({
                "status": "error",
                "code": "error_rate_limit",
                "content": f"Rate limit reached for this domain or ip, retry in {int(RATE_LIMIT_SECONDS - since_last_attempt)} seconds",
            }, status=400)

    RATE_LIMIT_DB[key] = time.time()


async def check_port_is_open(ip, port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((ip, port))
    return result == 0


async def query_dns(host, dns_entry_type):
    loop = asyncio.get_event_loop()
    dns_resolver = aiodns.DNSResolver(loop=loop)

    try:
        return await dns_resolver.query(host, dns_entry_type)
    except aiodns.error.DNSError:
        return []
    except Exception:
        import traceback
        traceback.print_exc()
        logger.error("Unhandled error while resolving DNS entry")


@app.route("/check-http/", methods=["POST"])
async def check_http(request):
    """
    This function received an HTTP request from a YunoHost instance while this
    server is hosted on our infrastructure. The request is expected to be a
    POST request with a body like {"domain": "domain-to-check.tld",
                                   "nonce": "1234567890abcdef" }

    The nonce value is a single-use ID, and we will try to reach
    http://domain.tld/.well-known/ynh-{nonce} which should return 200 if we
    are indeed reaching the right server.

    The general workflow is the following:

    - grab the ip from the request
    - check for ip based rate limit (see RATE_LIMIT_SECONDS value)
    - get json from body and domain from it
    - check for domain based rate limit (see RATE_LIMIT_SECONDS value)
    - check domain is in valid format
    - try to do an http request on the ip (using the domain as target host) for the page /.well-known/ynh-diagnosis/{nonce}
    - answer saying if the domain can be reached
    """

    # this is supposed to be a fast operation if run often enough
    now = time.time()
    clear_rate_limit_db(now)

    # ############################################# #
    #  Validate request and extract the parameters  #
    # ############################################# #

    ip = request.ip

    check_rate_limit_ip = check_rate_limit(ip, now)
    if check_rate_limit_ip:
        return check_rate_limit_ip

    try:
        data = request.json
    except InvalidUsage:
        logger.info(f"Invalid json in request, body is : {request.body}")
        return json_response({
            "status": "error",
            "code": "error_bad_json",
            "content": "Invalid usage, body isn't proper json",
        }, status=400)

    if not data or "domain" not in data or "nonce" not in data:
        logger.info(f"Unvalid request didn't specified a domain and a nonce id (body is : {request.body}")
        return json_response({
            "status": "error",
            "code": "error_no_domain",
            "content": "Request must specify a domain and a nonce",
        }, status=400)

    domain = data["domain"]

    check_rate_limit_domain = check_rate_limit(domain, now)
    if check_rate_limit_domain:
        return check_rate_limit_domain

    if not validators.domain(domain):
        logger.info(f"Invalid request, is not in the right format (domain is : {domain})")
        return json_response({
            "status": "error",
            "code": "error_domain_bad_format",
            "content": "domain is not in the right format (do not include http:// or https://)",
        }, status=400)

    nonce = data["nonce"]

    # nonce id is arbitrarily defined to be a
    # 16-digit hexadecimal string
    if not re.match(r"^[a-f0-9]{16}$", nonce):
        logger.info(f"Invalid request, is not in the right format (nonce is : {nonce})")
        return json_response({
            "status": "error",
            "code": "error_nonce_bad_format",
            "content": "nonce is not in the right format (it should be a 16-digit hexadecimal string)",
        }, status=400)

    # ############################################# #
    #  Run the actual check                         #
    # ############################################# #

    async with aiohttp.ClientSession() as session:
        try:
            url = "http://" + ip + "/.well-known/ynh-diagnosis/" + nonce
            async with session.get(url,
                                   headers={"Host": domain},
                                   timeout=aiohttp.ClientTimeout(total=30)) as response:
                # XXX in the futur try to do a double check with the server to
                # see if the correct content is get
                await response.text()
                assert response.status == 200
                logger.info(f"Success when checking http access for {domain} asked by {ip}")
        # TODO various kind of errors
        except aiohttp.client_exceptions.ClientConnectorError:
            return json_response({
                "status": "error",
                "code": "error_http_check_connection_error",
                "content": "connection error, could not connect to the requested domain, it's very likely unreachable",
            }, status=418)
        except Exception:
            import traceback
            traceback.print_exc()

            return json_response({
                "status": "error",
                "code": "error_http_check_unknown_error",
                "content": "an error happen while trying to get your domain, it's very likely unreachable",
            }, status=400)

    return json_response({"status": "ok"})


@app.route("/check-ports/", methods=["POST"])
async def check_ports(request):
    """
    This function received an HTTP request from a YunoHost instance while this
    server is hosted on our infrastructure. The request is expected to be a
    POST request with a body like {"ports": [80,443,22,25]}

    The general workflow is the following:

    - grab the ip from the request
    - check for ip based rate limit (see RATE_LIMIT_SECONDS value)
    - get json from body and ports list from it
    - check ports are opened or closed
    - answer the list of opened / closed ports
    """

    # this is supposed to be a fast operation if run often enough
    now = time.time()
    clear_rate_limit_db(now)

    # ############################################# #
    #  Validate request and extract the parameters  #
    # ############################################# #

    ip = request.ip

    check_rate_limit_ip = check_rate_limit(ip, now)
    if check_rate_limit_ip:
        return check_rate_limit_ip

    try:
        data = request.json
    except InvalidUsage:
        logger.info(f"Invalid json in request, body is : {request.body}")
        return json_response({
            "status": "error",
            "code": "error_bad_json",
            "content": "Invalid usage, body isn't proper json",
        }, status=400)

    def is_port_number(p):
        return isinstance(p, int) and p > 0 and p < 65535

    # Check "ports" exist in request and is a list of port
    if not data or "ports" not in data:
        logger.info(f"Unvalid request didn't specified a ports list (body is : {request.body}")
        return json_response({
            "status": "error",
            "code": "error_no_ports_list",
            "content": "Request must specify a list of ports to check",
        }, status=400)
    elif not isinstance(data["ports"], list) or any(not is_port_number(p) for p in data["ports"]) or len(data["ports"]) > 30 or data["ports"] == []:
        logger.info(f"Invalid request, ports list is not an actual list of ports, or is too long : {request.body}")
        return json_response({
            "status": "error",
            "code": "error_invalid_ports_list",
            "content": "This is not an acceptable port list : ports must be between 0 and 65535 and at most 30 ports can be checked",
        }, status=400)

    ports = set(data["ports"])  # Keep only a set so that we get unique ports

    # ############################################# #
    #  Run the actual check                         #
    # ############################################# #

    result = {}
    for port in ports:
        result[port] = await check_port_is_open(ip, port)

    return json_response({"status": "ok", "ports": result})


@app.route("/")
async def main(request):
    return html("You aren't really supposed to use this website using your browser.<br><br>It's a small server to check if a YunoHost instance can be reached by http before trying to instal a LE certificate.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000)
