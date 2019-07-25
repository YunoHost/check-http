import time
import asyncio
import aiodns
import aiohttp
import validators

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


@app.route("/check/", methods=["POST"])
async def check_http(request):
    """
    This function received an HTTP request from a YunoHost instance while this
    server is hosted on our infrastructure. The expected request body is:
    {"domain": "domain-to-check.tld"} and the method POST

    The general workflow is the following:

    - grab the ip from the request
    - check for ip based rate limit (see RATE_LIMIT_SECONDS value)
    - get json from body and domain from it
    - check for domain based rate limit (see RATE_LIMIT_SECONDS value)
    - check domain is in valid format
    - now try to do an http request on the ip using the domain as target host
    - answer saying if the domain can be reached
    """

    # this is supposed to be a fast operation if run often enough
    now = time.time()
    clear_rate_limit_db(now)

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

    if not data or "domain" not in data:
        logger.info(f"Unvalid request didn't specified a domain (body is : {request.body}")
        return json_response({
            "status": "error",
            "code": "error_no_domain",
            "content": "Request must specify a domain",
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

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get("http://" + ip,
                                   headers={"Host": domain},
                                   timeout=aiohttp.ClientTimeout(total=30)) as response:
                # XXX in the futur try to do a double check with the server to
                # see if the correct content is get
                await response.text()
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


@app.route("/")
async def main(request):
    return html("You aren't really supposed to use this website using your browser.<br><br>It's a small server to check if a YunoHost instance can be reached by http before trying to instal a LE certificate.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000)
