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
# Can't do more than 10 requests in a 300-seconds window
RATE_LIMIT_SECONDS = 300
RATE_LIMIT_NB_REQUESTS = 10

def clear_rate_limit_db(now):
    to_delete = []

    "Remove too old rate limit values"
    for key, times in RATE_LIMIT_DB.items():
        # Remove values older RATE_LIMIT_SECONDS
        RATE_LIMIT_DB[key] = [t for t in times if now - t < RATE_LIMIT_SECONDS]
        # If list is empty, remove the key
        if RATE_LIMIT_DB[key] == []:
            # a dictionnary can't be modified during iteration so delegate this
            # operation
            to_delete.append(key)

    for key in to_delete:
        del RATE_LIMIT_DB[key]


def check_rate_limit(key, now):

    # If there are more recent attempts than allowed
    if key in RATE_LIMIT_DB and len(RATE_LIMIT_DB[key]) > RATE_LIMIT_NB_REQUESTS:
        oldest_attempt = RATE_LIMIT_DB[key][0]
        logger.info(f"Rate limit reached for {key}, can retry in {int(RATE_LIMIT_SECONDS - now + oldest_attempt)} seconds")
        return json_response({
            "status": "error",
            "code": "error_rate_limit",
            "content": f"Rate limit reached for this domain or ip, retry in {int(RATE_LIMIT_SECONDS - now + oldest_attempt)} seconds",
        }, status=400)

    # In any case, add this attempt to the DB
    if key not in RATE_LIMIT_DB:
        RATE_LIMIT_DB[key] = [now]
    else:
        RATE_LIMIT_DB[key].append(now)


async def check_port_is_open(ip, port):

    if ":" in ip:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0


# FIXME : remove it ? not used anymore...
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

    ip = request.headers["x-forwarded-for"].split(",")[0]

    check_rate_limit_ip = check_rate_limit(ip, now)
    if check_rate_limit_ip:
        return check_rate_limit_ip

    try:
        data = request.json
    except InvalidUsage:
        logger.info(f"Invalid json in request, body is: {request.body}")
        return json_response({
            "status": "error",
            "code": "error_bad_json",
            "content": "Invalid usage, body isn't proper json",
        }, status=400)

    if not data or "domain" not in data or "nonce" not in data:
        logger.info(f"Invalid request: didn't specified a domain and a nonce id (body is: {request.body}")
        return json_response({
            "status": "error",
            "code": "error_no_domain_",
            "content": "Request must specify a domain and a nonce",
        }, status=400)

    domain = data["domain"]

    # Since now we are only checking the IP itself, it seems
    # unecessary to also have a rate limit on domains since the
    # rate limit on IP will be hit first ...
    # That would simplify some code, for example we could add the
    # rate limit check in a decorator for each route/check
    check_rate_limit_domain = check_rate_limit(domain, now)
    if check_rate_limit_domain:
        return check_rate_limit_domain

    if not validators.domain(domain):
        logger.info(f"Invalid request, is not in the right format (domain is: {domain})")
        return json_response({
            "status": "error",
            "code": "error_domain_bad_format",
            "content": "domain is not in the right format (do not include http:// or https://)",
        }, status=400)

    nonce = data["nonce"]

    # nonce id is arbitrarily defined to be a
    # 16-digit hexadecimal string
    if not re.match(r"^[a-f0-9]{16}$", nonce):
        logger.info(f"Invalid request, is not in the right format (nonce is: {nonce})")
        return json_response({
            "status": "error",
            "code": "error_nonce_bad_format",
            "content": "nonce is not in the right format (it should be a 16-digit hexadecimal string)",
        }, status=400)

    # ############################################# #
    #  Run the actual check                         #
    # ############################################# #

    if ":" in ip:
        ip = "[%s]" % ip

    async with aiohttp.ClientSession() as session:
        try:
            url = "http://" + ip + "/.well-known/ynh-diagnosis/" + nonce
            async with session.get(url,
                                   headers={"Host": domain},
                                   allow_redirects=False,
                                   timeout=aiohttp.ClientTimeout(total=10)) as response:
                # XXX in the futur try to do a double check with the server to
                # see if the correct content is get
                await response.text()
        # TODO various kind of errors
        except (aiohttp.client_exceptions.ServerTimeoutError, asyncio.TimeoutError):
            return json_response({
                "status": "error",
                "code": "error_http_check_timeout",
                "content": "Timed-out while trying to contact your server from outside. It appears to be unreachable. You should check that you're correctly forwarding port 80, that nginx is running, and that a firewall is not interfering.",
            }, status=418)
        except aiohttp.client_exceptions.ClientConnectorError as e:
            return json_response({
                "status": "error",
                "code": "error_http_check_connection_error",
                "content": "Connection error: could not connect to the requested domain, it's very likely unreachable. Raw error: " + str(e),
            }, status=418)
        except Exception as e:
            import traceback
            traceback.print_exc()

            return json_response({
                "status": "error",
                "code": "error_http_check_unknown_error",
                "content": "An error happened while trying to reach your domain, it's very likely unreachable. Raw error: %s" % e,
            }, status=400)

    if response.status != 200:
        return json_response({
            "status": "error",
            "code": "error_http_check_bad_status_code",
            "content": "Could not reach your server as expected, it returned code %s. It might be that another machine answered instead of your server. You should check that you're correctly forwarding port 80, that your nginx configuration is up to date, and that a reverse-proxy is not interfering." % response.status,
        }, status=418)
    else:
        logger.info(f"Success when checking http access for {domain} asked by {ip}")
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

    ip = request.headers["x-forwarded-for"].split(",")[0]

    check_rate_limit_ip = check_rate_limit(ip, now)
    if check_rate_limit_ip:
        return check_rate_limit_ip

    try:
        data = request.json
    except InvalidUsage:
        logger.info(f"Invalid json in request, body is: {request.body}")
        return json_response({
            "status": "error",
            "code": "error_bad_json",
            "content": "Invalid usage: body isn't proper json",
        }, status=400)

    def is_port_number(p):
        return isinstance(p, int) and p > 0 and p < 65535

    # Check "ports" exist in request and is a list of port
    if not data or "ports" not in data:
        logger.info(f"Invalid request didn't specified a ports list (body is: {request.body}")
        return json_response({
            "status": "error",
            "code": "error_no_ports_list",
            "content": "Request must specify a list of ports to check",
        }, status=400)
    elif not isinstance(data["ports"], list) or any(not is_port_number(p) for p in data["ports"]) or len(data["ports"]) > 30 or data["ports"] == []:
        logger.info(f"Invalid request, ports list is not an actual list of ports, or is too long: {request.body}")
        return json_response({
            "status": "error",
            "code": "error_invalid_ports_list",
            "content": "This is not an acceptable port list: ports must be between 0 and 65535 and at most 30 ports can be checked",
        }, status=400)

    ports = set(data["ports"])  # Keep only a set so that we get unique ports

    # ############################################# #
    #  Run the actual check                         #
    # ############################################# #

    result = {}
    for port in ports:
        result[int(port)] = await check_port_is_open(ip, port)

    return json_response({"status": "ok", "ports": result})


@app.route("/check-smtp/", methods=["POST"])
async def check_smtp(request):

    # TODO

    return json_reponse({"status": "error",
                         "code": "error_not_implemented_yet",
                         "content": "This is not yet implemented"})


@app.route("/")
async def main(request):
    return html("You aren't really supposed to use this website using your browser.<br><br>It's a small server with an API to check if a services running on YunoHost instance can be reached from 'the global internet'.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000)
