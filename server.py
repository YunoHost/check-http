import json

from sanic import Sanic
from sanic.response import html, json as json_response
from sanic.exceptions import InvalidUsage

app = Sanic()


@app.route("/check/", methods=["POST"])
async def check_http(request):
    from ipdb import set_trace; set_trace()
    ip = request.ip

    try:
        data = request.json
    except InvalidUsage:
        return json_response({
            "status": "error",
            "content": "InvalidUsage, body isn't proper json"
        })

    if "domain" not in data:
        return json_response({"status": "error", "content": "request must specify a domain"})

    domain = data["domain"]

    # TODO DNS check

    # [x] - get ip
    # [x] - get request json
    # [x] - in request json get domain target
    # [ ] - check dns that domain == ip
    # [ ] - if not, complain
    # [ ] - if everything is ok, try to get with http
    # [ ] - ADD TIMEOUT
    # [ ] - try/catch, if everything is ok → response ok
    # [ ] - otherwise reponse with exception

    return json_response({"status": "ok"})


@app.route("/")
async def main(request):
    return html("You aren't really supposed to use this website using your browser.<br><br>It's a small server to check if a YunoHost instance can be reached by http before trying to instal a LE certificate.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000)
