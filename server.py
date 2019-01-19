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
    - check dns entry for domain match the ip of the request (advanced rule for ipv6)
    - everything is checked, now try to do an http request on the domain
    - answer saying if the domain can be reached
    """

    # this is supposed to be a fast operation if run enough
    now = time.time()
    clear_rate_limit_db(now)

    ip = request.ip

    if ip in RATE_LIMIT_DB:
        since_last_attempt = now - RATE_LIMIT_DB[ip]
        if since_last_attempt < RATE_LIMIT_SECONDS:
            logger.info(f"Rate limite {ip}, can retry in {int(RATE_LIMIT_SECONDS - since_last_attempt)} seconds")
            return json_response({
                "status": "error",
                "code": "error_rate_limit",
                "content": f"Rate limit on ip, retry in {int(RATE_LIMIT_SECONDS - since_last_attempt)} seconds",
            }, status=400)

    RATE_LIMIT_DB[ip] = time.time()

    try:
        data = request.json
    except InvalidUsage:
        logger.info(f"Unvalid json in request, body is : {request.body}")
        return json_response({
            "status": "error",
            "code": "error_bad_json",
            "content": "InvalidUsage, body isn't proper json",
        }, status=400)

    if not data or "domain" not in data:
        logger.info(f"Unvalid request didn't specified a domain (body is : {request.body}")
        return json_response({
            "status": "error",
            "code": "error_no_domain",
            "content": "request must specify a domain",
        }, status=400)

    domain = data["domain"]

    if domain in RATE_LIMIT_DB:
        since_last_attempt = now - RATE_LIMIT_DB[domain]
        if since_last_attempt < RATE_LIMIT_SECONDS:
            logger.info(f"Rate limite {domain}, can retry in {int(RATE_LIMIT_SECONDS - since_last_attempt)} seconds")
            return json_response({
                "status": "error",
                "code": "error_rate_limit",
                "content": f"Rate limit on domain, retry in {int(RATE_LIMIT_SECONDS - since_last_attempt)} seconds",
            }, status=400)

    RATE_LIMIT_DB[domain] = time.time()

    if not validators.domain(domain):
        logger.info(f"Invalid request, is not in the right format (domain is : {domain})")
        return json_response({
            "status": "error",
            "code": "error_domain_bad_format",
            "content": "domain is not in the right format (do not include http:// or https://)",
        }, status=400)

    # TODO handle ipv6
    # ipv6 situation
    if ":" in ip:
        dns_entry = await query_dns(domain, "AAAA")

        if not dns_entry:
            # check if entry in ip4 for custom error
            dns_entry = await query_dns(domain, "A")

            # there is an ipv4 entry but the request is made in ipv6, ask to uses ipv4 instead
            if dns_entry:
                logger.info(f"[ipv6] Invalid request, no AAAA DNS entry for domain {domain} BUT ipv4 entry, ask user to request in ipv4")
                return json_response({
                    "status": "error",
                    "code": "error_no_ipv6_dns_entry_but_ipv4_dns_entry",
                    "content": f"there is not AAAA (ipv6) DNS entry for domain {domain} BUT there is an entry in ipv4, please redo the request in ipv4",
                }, status=400)

            else:
                logger.info(f"[ipv6] Invalid request, no DNS entry for domain {domain} (both in ipv6 and ip4)")
                return json_response({
                    "status": "error",
                    "code": "error_no_ipv4_ipv6_dns_entry_for_domain",
                    "content": f"there is not A (ipv4) and AAAA (ipv6) DNS entry for domain {domain}",
                }, status=400)
    # ipv4 situation
    else:
        dns_entry = await query_dns(domain, "A")

        if not dns_entry:
            logger.info(f"[ipv4] Invalid request, no DNS entry for domain {domain}")
            return json_response({
                "status": "error",
                "code": "error_no_ipv4_dns_entry_for_domain",
                "content": f"there is not A (ipv4) and AAAA (ipv6) DNS entry for domain {domain}",
            }, status=400)

    dns_entry = dns_entry[0]

    if dns_entry.host != ip:
        logger.info(f"Invalid request, A DNS entry {dns_entry.host} for domain {domain} doesn't match request ip {ip}")
        return json_response({
            "status": "error",
            "code": "error_dns_entry_doesnt_match_request_ip",
            "content": f"error, the request is made from the ip {ip} but the dns entry said {domain} has the ip {dns_entry.host}, you can only check a domain configured for your ip",
        }, status=400)

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get("http://" + domain, timeout=aiohttp.ClientTimeout(total=30)) as response:
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
            }, status=400)
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
