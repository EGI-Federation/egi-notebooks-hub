import httpx
from fastapi import FastAPI, Request

app = FastAPI()

AUTH_HEADER = "Authorization"
TOKEN_TYPE = "bearer"
URL = "http://localhost:8000/hub/jwt_login"
API_URL = "http://localhost:8000/hub/api"
PREFIX = "services/jwt"


# this could be way more generic and moved to a base function and then
# a thin wrapper for get/put/post/etc...
@app.get("/{svc_path:path}")
async def api_wrapper(request: Request, svc_path: str):
    user_token = {}
    if AUTH_HEADER in request.headers:
        f = request.headers[AUTH_HEADER].split()
        if len(f) == 2 and f[0].lower() == TOKEN_TYPE:
            async with httpx.AsyncClient() as client:
                r = await client.get(
                    URL, headers={AUTH_HEADER: request.headers[AUTH_HEADER]}
                )
                # errors should kick me out
                user_token = r.json()
    # assume we have the user_token here
    api_path = svc_path.removeprefix(PREFIX)
    async with httpx.AsyncClient() as client:
        # which headers do we need to preserve?
        headers = {"Authorization": f"token {user_token['token']}"}
        r = await client.get(API_URL + api_path, headers=headers)
        # is this a correct assumption?
        return r.json()
