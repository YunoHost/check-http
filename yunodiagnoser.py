import re
import time
import asyncio
import aiohttp
import validators
import socket

from sanic import Sanic
from sanic.log import logger
from sanic.response import html, json as json_response
from sanic.exceptions import InvalidUsage

app = Sanic()

# ########################################################################### #
#   Rate limit                                                                #
# ########################################################################### #

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
            "error": {
                "code": "error_rate_limit",
                "content": f"Rate limit reached for this domain or ip, retry in {int(RATE_LIMIT_SECONDS - now + oldest_attempt)} seconds"
            }
        }, status=400)

    # In any case, add this attempt to the DB
    if key not in RATE_LIMIT_DB:
        RATE_LIMIT_DB[key] = [now]
    else:
        RATE_LIMIT_DB[key].append(now)


# ########################################################################### #
#   HTTP check                                                                #
# ########################################################################### #


@app.route("/check-http", methods=["POST"])
async def check_http(request):
    """
    This function received an HTTP request from a YunoHost instance while this
    server is hosted on our infrastructure. The request is expected to be a
    POST request with a body like {"domains": ["domain1.tld", "domain2.tld"],
                                   "nonce": "1234567890abcdef" }

    The nonce value is a single-use ID, and we will try to reach
    http://domain.tld/.well-known/ynh-{nonce} which should return 200 if we
    are indeed reaching the right server.

    The general workflow is the following:

    - grab the ip from the request
    - check for ip based rate limit (see RATE_LIMIT_SECONDS value)
    - get json from body and domain from it
    - check for domain-based rate limit (see RATE_LIMIT_SECONDS value)
    - check domains are in valid format
    - for each domain:
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
            "error": {
                "code": "error_bad_json",
                "content": "Invalid usage, body isn't proper json"
            }
        }, status=400)

    try:
        assert data, "Empty request body"
        assert isinstance(data, dict), "Request body ain't a proper dict"
        assert "domains" in data, "No 'domains' provided"
        assert "nonce" in data, "No 'nonce' provided"

        # Check domain list format
        assert isinstance(data["domains"], list), "'domains' ain't a list"
        assert len(data["domains"]) > 0, "'domains' list is empty"
        assert len(data["domains"]) < 30, "You cannot test that many domains"
        for domain in data["domains"]:
            assert isinstance(domain, str), "domain names must be strings"
            assert len(domain) < 100, "Domain %s name seems pretty long, that's suspicious...?" % domain
        assert len(data["domains"]) == len(set(data["domains"])), "'domains' list should contain unique elements"

        # Check domain rate limit
        for domain in data["domains"]:
            check_rate_limit_domain = check_rate_limit(domain, now)
            if check_rate_limit_domain:
                return check_rate_limit_domain

        # Check domains are valid domain names
        for domain in data["domains"]:
            assert validators.domain(domain), f"{domain} is not a valid domain"

        # Check nonce format
        assert isinstance(data["nonce"], str), "'nonce' ain't a string"
        assert re.match(r"^[a-f0-9]{16}$", data["nonce"]), "'nonce' is not in the right forwat (it should be a 16-digit hexadecimal string)"
    except AssertionError as e:
        logger.info(f"Invalid request: {e} ... Original request body was: {request.body}")
        return json_response({
            "error": {
                "code": "error_bad_json_data",
                "content": f"Invalid request: {e} ... Original request body was: {request.body}"
            }
        }, status=400)

    domains = data["domains"]
    nonce = data["nonce"]

    return json_response({
        "http": {domain: await check_http_domain(ip, domain, nonce) for domain in domains}
    })


async def check_http_domain(ip, domain, nonce):

    if ":" in ip:
        ip = "[%s]" % ip

    async with aiohttp.ClientSession() as session:
        try:
            url = "http://" + ip + "/.well-known/ynh-diagnosis/" + nonce
            async with session.get(url,
                                   headers={"Host": domain},
                                   allow_redirects=False,
                                   timeout=aiohttp.ClientTimeout(total=5)) as response:
                # XXX in the futur try to do a double check with the server to
                # see if the correct content is get
                await response.text()
        # TODO various kind of errors
        except (aiohttp.client_exceptions.ServerTimeoutError, asyncio.TimeoutError):
            return {
                "status": "error_http_check_timeout",
                "content": "Timed-out while trying to contact your server from outside. It appears to be unreachable. You should check that you're correctly forwarding port 80, that nginx is running, and that a firewall is not interfering.",
            }
        except aiohttp.client_exceptions.ClientConnectorError as e:
            return {
                "status": "error_http_check_connection_error",
                "content": "Connection error: could not connect to the requested domain, it's very likely unreachable. Raw error: " + str(e),
            }
        except Exception as e:
            import traceback
            traceback.print_exc()

            return {
                "status": "error_http_check_unknown_error",
                "content": "An error happened while trying to reach your domain, it's very likely unreachable. Raw error: %s" % e,
            }

    if response.status != 200:
        return {
            "status": "error_http_check_bad_status_code",
            "content": "Could not reach your server as expected, it returned code %s. It might be that another machine answered instead of your server. You should check that you're correctly forwarding port 80, that your nginx configuration is up to date, and that a reverse-proxy is not interfering." % response.status,
        }
    else:
        return {
            "status": "ok"
        }


# ########################################################################### #
#   Ports check                                                               #
# ########################################################################### #


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
            "error": {
                "code": "error_bad_json",
                "content": "Invalid usage, body isn't proper json"
            }
        }, status=400)

    try:
        assert data, "Empty request body"
        assert isinstance(data, dict), "Request body ain't a proper dict"
        assert "ports" in data, "No 'ports' provided"

        assert isinstance(data["ports"], list), "'ports' ain't a list"
        assert len(data["ports"]) > 0, "'ports' list is empty"
        assert len(data["ports"]) < 30, "That's too many ports to check"
        assert len(data["ports"]) == len(set(data["ports"])), "'ports' list should contain unique elements"

        def is_port_number(p):
            return isinstance(p, int) and p > 0 and p < 65535
        assert all(is_port_number(p) for p in data["ports"]), "'ports' should a list of valid port numbers"
    except AssertionError as e:
        logger.info(f"Invalid request: {e} ... Original request body was: {request.body}")
        return json_response({
            "error": {
                "code": "error_bad_json_data",
                "content": f"Invalid request: {e} ... Original request body was: {request.body}"
            }
        }, status=400)

    # ############################################# #
    #  Run the actual check                         #
    # ############################################# #

    result = {}
    for port in data["ports"]:
        result[int(port)] = await check_port_is_open(ip, port)

    return json_response({"ports": result})


async def check_port_is_open(ip, port):

    if ":" in ip:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0


# ########################################################################### #
#   SMTP check                                                                #
# ########################################################################### #


@app.route("/check-smtp/", methods=["POST"])
async def check_smtp(request):
    """
    This function received an HTTP request from a YunoHost instance while this
    server is hosted on our infrastructure. The request is expected to be a
    POST request with an empty body

    The general workflow is the following:

    - grab the ip from the request
    - check for ip based rate limit (see RATE_LIMIT_SECONDS value)
    - open a socket on port 25
    - the server is supposed to say '200 domain.tld Service ready'
    - we return the domain.tld found
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

    if ":" in ip:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.settimeout(2)
    result = sock.connect_ex((ip, 25))
    if result != 0:
        return json_response({
            'status': "error_smtp_unreachable",
            'content': "Could not open a connection on port 25, probably because of a firewall or port forwarding issue"
        })

    try:
        recv = sock.recv(1024).decode('utf-8')
        assert recv[:3] == "220"
        helo_domain = recv.split()[1].strip()
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error when trying to get smtp answer: {e}")
        return json_response({
            'status': "error_smtp_bad_answer",
            'content': "SMTP server did not reply with '220 domain.tld' after opening socket ... Maybe another machine answered."
        })
    finally:
        sock.close()

    return json_response({'status': 'ok', 'helo': helo_domain})


@app.route("/")
async def main(request):
    return html("You aren't really supposed to use this website using your browser.<br><br>It's a small server with an API to check if a services running on YunoHost instance can be reached from 'the global internet'.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000)
