import aiohttp
import validators

from sanic import Sanic
from sanic.log import logger
from sanic.response import html, json as json_response
from sanic.exceptions import InvalidUsage

app = Sanic()


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

    # TODO DNS check

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
    # [ ] - validate domain is in correct format
    # [ ] - check dns that domain == ip
    # [ ] - if not, complain
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
