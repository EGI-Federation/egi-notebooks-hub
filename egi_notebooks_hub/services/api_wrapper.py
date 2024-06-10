import httpx
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()

AUTH_HEADER = "authorization"
TOKEN_TYPE = "bearer"
URL = "http://localhost:8000/hub/jwt_login"
API_URL = "http://localhost:8000/hub/api"
PREFIX = "services/jwt"


# wrapping all the HTTP actions in a single function
@app.get("/{svc_path:path}")
@app.put("/{svc_path:path}")
@app.post("/{svc_path:path}")
@app.delete("/{svc_path:path}")
@app.options("/{svc_path:path}")
@app.head("/{svc_path:path}")
@app.patch("/{svc_path:path}")
@app.trace("/{svc_path:path}")
async def api_wrapper(request: Request, svc_path: str):
    token_header = {}
    if AUTH_HEADER in request.headers:
        f = request.headers[AUTH_HEADER].split()
        if len(f) == 2 and f[0].lower() == TOKEN_TYPE:
            try:
                async with httpx.AsyncClient() as client:
                    r = await client.get(
                        URL, headers={AUTH_HEADER: request.headers[AUTH_HEADER]}
                    )
                    r.raise_for_status()
                    user_token = r.json()
                    token_header[AUTH_HEADER] = f"token {user_token['token']}"
            except httpx.HTTPStatusError as exc:
                raise HTTPException(
                    status_code=exc.response.status_code, detail=exc.response.text
                )
    content = await request.body()
    api_path = svc_path.removeprefix(PREFIX)
    async with httpx.AsyncClient() as client:
        # which headers do we need to preserve?
        headers = dict(request.headers)
        if AUTH_HEADER in headers:
            del headers[AUTH_HEADER]
        headers.update(token_header)
        method = getattr(client, request.method.lower())
        if content:
            r = await method(API_URL + api_path, content=content, headers=headers)
        else:
            r = await method(API_URL + api_path, headers=headers)
        # is this a correct assumption?
        return r.json()
