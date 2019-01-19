import asyncio
import aiodns
import aiohttp
import validators

from sanic import Sanic
from sanic.log import logger
from sanic.response import html, json as json_response
from sanic.exceptions import InvalidUsage

app = Sanic()


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
    ip = request.ip

    try:
        data = request.json
    except InvalidUsage:
        logger.info(f"Unvalid json in request, body is : {request.body}")
        return json_response({
            "status": "error",
            "code": "error_bad_json",
            "content": "InvalidUsage, body isn't proper json",
        })

    if not data or "domain" not in data:
        logger.info(f"Unvalid request didn't specified a domain (body is : {request.body}")
        return json_response({
            "status": "error",
            "code": "error_no_domain",
            "content": "request must specify a domain",
        })

    domain = data["domain"]

    if not validators.domain(domain):
        logger.info(f"Invalid request, is not in the right format (domain is : {domain})")
        return json_response({
            "status": "error",
            "code": "error_domain_bad_format",
            "content": "domain is not in the right format (do not include http:// or https://)",
        })

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
                })

            else:
                logger.info(f"[ipv6] Invalid request, no DNS entry for domain {domain} (both in ipv6 and ip4)")
                return json_response({
                    "status": "error",
                    "code": "error_no_ipv4_ipv6_dns_entry_for_domain",
                    "content": f"there is not A (ipv4) and AAAA (ipv6) DNS entry for domain {domain}",
                })
    # ipv4 situation
    else:
        dns_entry = await query_dns(domain, "A")

        if not dns_entry:
            logger.info(f"[ipv4] Invalid request, no DNS entry for domain {domain}")
            return json_response({
                "status": "error",
                "code": "error_no_ipv4_dns_entry_for_domain",
                "content": f"there is not A (ipv4) and AAAA (ipv6) DNS entry for domain {domain}",
            })

    dns_entry = dns_entry[0]

    if dns_entry.host != ip:
        logger.info(f"Invalid request, A DNS entry {dns_entry.host} for domain {domain} doesn't match request ip {ip}")
        return json_response({
            "status": "error",
            "code": "error_dns_entry_doesnt_match_request_ip",
            "content": f"error, the request is made from the ip {ip} but the dns entry said {domain} has the ip {dns_entry.host}, you can only check a domain configured for your ip",
        })

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
            })
        except Exception:
            import traceback
            traceback.print_exc()

            return json_response({
                "status": "error",
                "code": "error_http_check_unknown_error",
                "content": "an error happen while trying to get your domain, it's very likely unreachable",
            })

    # [x] - get ip
    # [x] - get request json
    # [x] - in request json get domain target
    # [x] - validate domain is in correct format
    # [x] - check dns that domain == ip
    # [x] - if not, complain
    # [x] - handle ipv6
    # [x] - if everything is ok, try to get with http
    # [x] - ADD TIMEOUT
    # [x] - try/catch, if everything is ok → response ok
    # [x] - otherwise reponse with exception
    # [x] - create error codes
    # [ ] - rate limit

    return json_response({"status": "ok"})


@app.route("/")
async def main(request):
    return html("You aren't really supposed to use this website using your browser.<br><br>It's a small server to check if a YunoHost instance can be reached by http before trying to instal a LE certificate.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000)
