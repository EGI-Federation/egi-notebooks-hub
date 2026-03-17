"""
A service to manage shares and release access tokens for running servers

It wraps some of the sharing functions of the Hub API with extra checks to
ensure access tokens cannot be obtained when the server is shared.

It requires the service to be configured with the right scopes:
* `read:users` to get information about the users
* `read:tokens` to get information about the tokens from the jupyter server
* `admin:auth_state` to read the access token available in `auth_state`
* `shares` to manage the user shares

Sample configuration:
```
c.JupyterHub.load_roles = [
    {
        'name': 'user',
        'description': 'Grant users access to hub services',
        'scopes': ["access:services", "self"],
    },
    {
        "name": "share-manager",
        "scopes": ["read:users", "admin:auth_state", "read:tokens", "shares"],
        "services": ["share-manager"]
    }
]

c.JupyterHub.services = [
    {
        'name': 'share-manager',
        # tune the port and host to listen on with --port and --host options
        'command': [
            'fastapi',
            'run',
            '-e',
            'egi_notebooks_hub.services.share_manager:app',
        ],
    }
]
```

Only tokens with the scope configured in `Settings.token_acquirer_scope` will be able
to obtain the access_token, e.g. for adding this scope in the browser token:

```
# custom:token-acquirer:read is the default value
c.JupyterHub.custom_scopes = {
    "custom:token-acquirer:read": {
        "description": "Access to token acquirer",
    },
}
c.Spawner.oauth_client_allowed_scopes = ["custom:token-acquirer:read"]
```
"""

import logging
import re
from typing import List, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from jupyterhub.utils import url_path_join
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    auth_header: str = "authorization"
    token_types: List[str] = ["bearer", "token"]
    jupyterhub_service_prefix: str = "/services/share-manager"
    jupyterhub_api_url: str = "http://localhost:8000/hub/api"
    token_revoke_path: str = "/token_revoke"
    api_timeout: float = 15.0
    jupyterhub_api_token: str = "token"
    token_acquirer_scope: str = "custom:token-acquirer:read"


settings = Settings()
app = FastAPI(root_path=settings.jupyterhub_service_prefix.rstrip("/"))

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()
logger.info(f"Targetting {settings.jupyterhub_api_url} as API URL")
logger.info(f"Service listening under {settings.jupyterhub_service_prefix}")


# mimic jupyterhub where errors are shown with "message"
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code, content={"message": str(exc.detail)}
    )


def get_user_token(request: Request):
    if settings.auth_header not in request.headers:
        raise HTTPException(status_code=401, detail="Missing authentication header")
    token_header = request.headers[settings.auth_header].split()
    if len(token_header) == 2 and token_header[0].lower() in settings.token_types:
        return token_header[1]
    raise HTTPException(status_code=401, detail="Missing authentication header")


def get_server_name(token_info: dict):
    oauth_client = token_info.get("oauth_client", "")
    session_id = token_info.get("session_id", None)
    logger.debug(
        f"User {token_info['user']} with session {session_id}"
        f" and oauth_client {oauth_client}"
    )
    if not (session_id and oauth_client):
        return None
    if not oauth_client.lower().startswith("server at"):
        return None
    # XXX parsing the oauth_client for the server name, this may break!
    server_name = ""
    server_path = oauth_client.rsplit(maxsplit=1)[-1].strip("/").split("/")
    if len(server_path) > 2:
        server_name = server_path[-1]
    logger.debug(f"Server name is `{server_name}`")
    return server_name


async def call_hub_api(
    path,
    base_url=None,
    content=None,
    method="get",
    headers={},
    token=None,
):
    if not base_url:
        base_url = settings.jupyterhub_api_url
    url = url_path_join(base_url, path)
    if token:
        headers.update({"authorization": f"bearer {token}"})
    async with httpx.AsyncClient(timeout=settings.api_timeout) as client:
        method_f = getattr(client, method.lower())
        logger.info(f"Call hub - target call: {url}")
        if content:
            r = await method_f(url, content=content, headers=headers)
        else:
            r = await method_f(url, headers=headers)
        if r.status_code != httpx.codes.OK:
            logger.debug(f"Error from upstream server {r.content}")
            raise HTTPException(r.status_code, detail=r.content.decode())
        try:
            return r.json()
        except ValueError:
            return r.content


async def get_user_info(request: Request, check_ownership: bool = True):
    user_token = get_user_token(request)
    user_info = await call_hub_api(path="user", token=user_token)
    if check_ownership:
        access_scope_re = re.compile(f"access:servers!server={user_info['name']}/.*")
        if not any(access_scope_re.match(scope) for scope in user_info.get("scopes", [])):
            raise HTTPException(
                403, detail="Forbidden, server access does not match token owner!"
            )
    return user_info, user_token


@app.get("/token")
async def get_token(request: Request):
    """Gets access token from the auth_state.

    It will return the access token if:
    1. the calling token owner is the same as the server owner
    1. the calling token has the scope configured in `token_acquirer_scope`
    2. the calling token is associated to a running server
    3. the server is not shared
    """
    logger.debug("Get token request")
    user_info, user_token = await get_user_info(request)

    token_info = await call_hub_api(
        path=f"users/{user_info['name']}/tokens/{user_info['token_id']}",
        token=settings.jupyterhub_api_token,
    )
    if settings.token_acquirer_scope not in token_info["scopes"]:
        raise HTTPException(
            403, detail=f"Forbidden, requires {settings.token_acquirer_scope} scope!"
        )
    server_name = get_server_name(token_info)
    if server_name is None:
        raise HTTPException(403, detail="Forbidden, no server token!")
    shares = await call_hub_api(
        path=f"shares/{user_info['name']}/{server_name}",
        token=settings.jupyterhub_api_token,
    )
    share_codes = await call_hub_api(
        path=f"share-codes/{user_info['name']}/{server_name}",
        token=settings.jupyterhub_api_token,
    )
    if shares.get("items", []) or share_codes.get("items", []):
        msg = "You have shared access to your server, remove it to issue access_token"
        raise HTTPException(403, detail=msg)
    user_data = await call_hub_api(
        path=f"users/{user_info['name']}",
        token=settings.jupyterhub_api_token,
    )
    access_token = None
    auth_state = user_data.get("auth_state", {})
    if auth_state:
        access_token = auth_state.get("access_token", None)
    if not access_token:
        raise HTTPException(404, detail="No access token available for the user")
    return {"access_token": access_token}


async def call_wrapper(request: Request, path: str):
    """Wraps calls the the HUP API using our token"""
    logger.debug(f"Wrapping call to {path}")
    _, user_token = await get_user_info(request)
    resp = await call_hub_api(
        path=path,
        method=request.method.lower(),
        content=await request.body(),
        headers=dict(request.headers),
        token=settings.jupyterhub_api_token,
    )
    return resp


@app.post("/share-codes/{owner:str}/")
@app.post("/share-codes/{owner:str}/{server_name:str}")
async def create_share_code(
    request: Request, owner: str, server_name: Optional[str] = ""
):
    """Creates a share code for an owner and server.

    Wraps the JupyterHub API call for creating a share code by
    revoking first access tokens of the user.
    """
    logger.debug("Share code post called")
    _, user_token = await get_user_info(request)
    shares = await call_hub_api(
        path=f"shares/{owner}/{server_name}",
        token=settings.jupyterhub_api_token,
    )
    share_codes = await call_hub_api(
        path=f"share-codes/{owner}/{server_name}",
        token=settings.jupyterhub_api_token,
    )
    if not (shares.get("items", []) or share_codes.get("items", [])):
        # First revoke the token as the server is shared
        hub_url = settings.jupyterhub_api_url.rstrip("/").removesuffix("/api")
        await call_hub_api(
            path=settings.token_revoke_path,
            base_url=hub_url,
            method="post",
            token=user_token,
        )
    # 2. Then create sharing - just redirect the call
    resp = await call_hub_api(
        path=f"/share-codes/{owner}/{server_name}",
        method="post",
        content=await request.body(),
        headers=dict(request.headers),
        token=settings.jupyterhub_api_token,
    )
    return resp


@app.delete("/share-codes/{svc_path:path}")
async def delete_share_codes(request: Request, svc_path: str):
    return await call_wrapper(request, f"share-codes/{svc_path}")


@app.get("/shares/{svc_path:path}")
@app.patch("/shares/{svc_path:path}")
@app.delete("/shares/{svc_path:path}")
async def wrap_shares(request: Request, svc_path: str):
    return await call_wrapper(request, f"shares/{svc_path}")
