#!/usr/bin/env python3

import asyncio
import re
import socket
import time
from argparse import ArgumentParser

import aiohttp
import validators
from aiohttp.client_exceptions import ClientConnectorError, ServerTimeoutError
from sanic import Sanic
from sanic.exceptions import InvalidUsage
from sanic.log import logger
from sanic.request import Request
from sanic.response import HTTPResponse, html
from sanic.response import json as json_response

app = Sanic(__name__)

logger = logger  # noqa: PLW0127  This assignment is here for linter

# ########################################################################### #
#   Rate limit                                                                #
# ########################################################################### #

# keep that in memory
RATE_LIMIT_DB = {}

# to prevent DDoS or bounce attack attempt or something like that
# Can't do more than 10 requests in a 300-seconds window
RATE_LIMIT_SECONDS = 300
RATE_LIMIT_NB_REQUESTS = 10


def clear_rate_limit_db(now: float) -> None:
    """Remove too old rate limit values"""
    to_delete = []

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


def check_rate_limit(key: str, now: float) -> HTTPResponse | None:
    # If there are more recent attempts than allowed
    if key in RATE_LIMIT_DB and len(RATE_LIMIT_DB[key]) > RATE_LIMIT_NB_REQUESTS:
        oldest_attempt = RATE_LIMIT_DB[key][0]
        next_attempt = int(RATE_LIMIT_SECONDS - now + oldest_attempt)
        msg = f"Rate limit reached for {key}, can retry in {next_attempt} seconds"
        logger.info(msg)
        return json_response(
            {"error": {"code": "error_rate_limit", "content": msg}}, status=400
        )

    # In any case, add this attempt to the DB
    if key not in RATE_LIMIT_DB:
        RATE_LIMIT_DB[key] = [now]
    else:
        RATE_LIMIT_DB[key].append(now)
    return None


# ########################################################################### #
#   HTTP check                                                                #
# ########################################################################### #


@app.route("/check-http", methods=["POST"])
async def check_http(request: Request) -> HTTPResponse:
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
        - try to do an http request on the ip (using the domain as target host)
          for the page /.well-known/ynh-diagnosis/{nonce}
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
        msg = f"Invalid json in request, body isn't proper json (is: {request.body})"
        logger.info(msg)
        return json_response(
            {"error": {"code": "error_bad_json", "content": msg}}, status=400
        )

    try:
        assert data, "Empty request body"
        assert isinstance(data, dict), "Request body ain't a proper dict"
        assert "domains" in data, "No 'domains' provided"
        assert "nonce" in data, "No 'nonce' provided"

        # Check domain list format
        assert isinstance(data["domains"], list), "'domains' ain't a list"
        assert len(data["domains"]) > 0, "'domains' list is empty"
        assert len(data["domains"]) < request.app.config.MAX_DOMAINS, (
            "You cannot test that many domains"
        )
        for domain in data["domains"]:
            assert isinstance(domain, str), "domain names must be strings"
            assert len(domain) < 100, (
                f"Domain {domain} name seems pretty long, that's suspicious...?"
            )
        assert len(data["domains"]) == len(set(data["domains"])), (
            "'domains' list should contain unique elements"
        )

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
        assert re.match(r"^[a-f0-9]{16}$", data["nonce"]), (
            "'nonce' is not in the right forwat (it should be a 16-digit "
            "hexadecimal string)"
        )
    except AssertionError as e:
        msg = f"Invalid request: {e} ... Original request body was: {request.body}"
        logger.info(msg)
        return json_response(
            {"error": {"code": "error_bad_json_data", "content": msg}}, status=400
        )

    domains = data["domains"]
    nonce = data["nonce"]

    result = {domain: await check_http_domain(ip, domain, nonce) for domain in domains}
    return json_response({"http": result})


async def check_http_domain(ip: str, domain: str, nonce: str) -> dict[str, str]:
    # Handle IPv6
    if ":" in ip:
        ip = f"[{ip}]"

    async with aiohttp.ClientSession() as session:
        try:
            url = f"http://{ip}/.well-known/ynh-diagnosis/{nonce}"
            async with session.get(
                url,
                headers={"Host": domain},
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=5),
            ) as response:
                # XXX in the futur try to do a double check with the server to
                # see if the correct content is get
                await response.text()
        # TODO various kind of errors
        except (ServerTimeoutError, TimeoutError):
            msg = (
                "Timed-out while trying to contact your server from outside. "
                "It appears to be unreachable. You should check that you're "
                "correctly forwarding port 80, that nginx is running, and that "
                "a firewall is not interfering."
            )
            return {"status": "error_http_check_timeout", "content": msg}
        except (OSError, ClientConnectorError) as e:
            # OSError: [Errno 113] No route to host
            msg = (
                "Connection error: could not connect to the requested domain, "
                f"it's very likely unreachable. Raw error: {e}"
            )
            return {"status": "error_http_check_connection_error", "content": msg}
        except Exception as e:
            logger.exception("While trying to reach domain")
            msg = (
                "An error happened while trying to reach your domain, "
                f"it's very likely unreachable. Raw error: {e}"
            )
            return {"status": "error_http_check_unknown_error", "content": msg}

    if response.status != 200:
        msg = (
            "Could not reach your server as expected, it returned code "
            f"{response.status}. It might be that another machine answered instead of "
            "your server. You should check that you're correctly forwarding port 80, "
            "that your nginx configuration is up to date, and that a reverse-proxy "
            "is not interfering."
        )
        return {"status": "error_http_check_bad_status_code", "content": msg}

    return {"status": "ok"}


# ########################################################################### #
#   Ports check                                                               #
# ########################################################################### #


@app.route("/check-ports/", methods=["POST"])
async def check_ports(request: Request) -> HTTPResponse:
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
        msg = f"Invalid usage, body isn't proper json (body is {request.body}"
        logger.info(msg)
        return json_response(
            {"error": {"code": "error_bad_json", "content": msg}}, status=400
        )

    try:
        assert data, "Empty request body"
        assert isinstance(data, dict), "Request body ain't a proper dict"
        assert "ports" in data, "No 'ports' provided"

        assert isinstance(data["ports"], list), "'ports' ain't a list"
        assert len(data["ports"]) > 0, "'ports' list is empty"
        assert len(data["ports"]) < request.app.config.MAX_PORTS, (
            "That's too many ports to check"
        )
        assert len(data["ports"]) == len(set(data["ports"])), (
            "'ports' list should contain unique elements"
        )

        def is_port_number(p: int) -> bool:
            return isinstance(p, int) and p > 0 and p < 65535

        assert all(is_port_number(p) for p in data["ports"]), (
            "'ports' should a list of valid port numbers"
        )
    except AssertionError as e:
        msg = f"Invalid request: {e} ... Original request body was: {request.body}"
        logger.info(msg)
        return json_response(
            {"error": {"code": "error_bad_json_data", "content": msg}}, status=400
        )

    # ############################################# #
    #  Run the actual check                         #
    # ############################################# #

    result = {}
    for port in data["ports"]:
        result[int(port)] = await check_port_is_open(ip, port)

    return json_response({"ports": result})


async def check_port_is_open(ip: str, port: int) -> bool:
    if ":" in ip:
        futur = asyncio.open_connection(ip, port, family=socket.AF_INET6)
    else:
        futur = asyncio.open_connection(ip, port, family=socket.AF_INET)

    try:
        _, writer = await asyncio.wait_for(futur, timeout=2)
    except (TimeoutError, ConnectionRefusedError, OSError):
        # OSError: [Errno 113] No route to host
        return False
    except Exception:
        logger.exception("While checking open port")
        return False
    else:
        writer.close()
        # XXX we are still in python 3.6 in prod :(
        # await writer.wait_closed()

        return True


# ########################################################################### #
#   SMTP check                                                                #
# ########################################################################### #


@app.route("/check-smtp/", methods=["POST"])
async def check_smtp(request: Request) -> HTTPResponse:
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
        futur = asyncio.open_connection(ip, 25, family=socket.AF_INET6)
    else:
        futur = asyncio.open_connection(ip, 25, family=socket.AF_INET)

    try:
        reader, writer = await asyncio.wait_for(futur, timeout=2)
    except (TimeoutError, ConnectionRefusedError, OSError):
        # OSError: [Errno 113] No route to host
        msg = (
            "Could not open a connection on port 25, probably because of "
            "a firewall or port forwarding issue",
        )
        return json_response({"status": "error_smtp_unreachable", "content": msg})
    except Exception:
        msg = (
            "Could not open a connection on port 25, probably because of "
            "a firewall or port forwarding issue",
        )
        logger.exception(msg)
        return json_response({"status": "error_smtp_unreachable", "content": msg})

    try:
        recv = await asyncio.wait_for(reader.read(1024), timeout=200)
        recv = recv.decode("Utf-8")
        assert recv[:3] == "220"
        helo_domain = recv.split()[1].strip()
    except TimeoutError:
        msg = "SMTP server took more than 2 seconds to answer."
        return json_response({"status": "error_smtp_timeout_answer", "content": msg})
    except Exception:
        msg = (
            "SMTP server did not reply with '220 domain.tld' after opening socket... "
            "Maybe another machine answered."
        )
        logger.exception(msg)
        return json_response({"status": "error_smtp_bad_answer", "content": msg})
    finally:
        writer.close()
        # XXX we are still in python 3.6 in prod :(
        # await writer.wait_closed()

    return json_response({"status": "ok", "helo": helo_domain})


@app.route("/")
async def main(request: Request) -> HTTPResponse:
    return html(
        "You aren't really supposed to use this website using your browser.<br><br>"
        "It's a small server with an API to check if a services running on YunoHost "
        "instance can be reached from 'the global internet'."
    )


def serve() -> None:
    parser = ArgumentParser("yunodiagnoser.py")
    parser.add_argument("--host", help="Address to host on", default="0.0.0.0")
    parser.add_argument("--port", help="Port to host on", default=7000, type=int)
    parser.add_argument(
        "--workers",
        help="Number of processes received before it is respected",
        default=16,
        type=int,
    )
    parser.add_argument(
        "--debug", help="Enables debug output (slows server)", action="store_true"
    )
    parser.add_argument(
        "--auto-reload",
        help=(
            "Reload app whenever its source code is changed. "
            "Enabled by default in debug mode."
        ),
        default=None,
        action="store_true",
    )

    # Settings
    parser.add_argument(
        "--max-domains",
        help="Maximum domains allowed to check in a batch",
        default=60,
        type=int,
    )
    parser.add_argument(
        "--max-ports",
        help="Maximum ports allowed to check in a batch",
        default=30,
        type=int,
    )

    args, _ = parser.parse_known_args()

    app.config.MAX_DOMAINS = args.max_domains
    app.config.MAX_PORTS = args.max_ports

    app.run(
        host=args.host,
        port=args.port,
        workers=args.workers,
        debug=args.debug,
        auto_reload=args.auto_reload,
    )


if __name__ == "__main__":
    serve()
