"""
A service to manage shares and release access tokens for running servers

It wraps some of the sharing functions of the Hub API with extra checks to
ensure access tokens cannot be obtained when the server is shared.

It requires the service to be configured with the right scopes:
* `read:users` to get information about the users
* `read:servers` to get information about the user servers
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

import json
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
    api_timeout: float = 15.0
    token_types: List[str] = ["bearer", "token"]
    jupyterhub_service_prefix: str = "/services/share-manager"
    jupyterhub_api_url: str = "http://localhost:8000/hub/api"
    # path of the revocation call of the authenticator
    token_revoke_path: str = "/token_revoke"
    # A jupyterhub token with the following scopes:
    # "read:users", "admin:auth_state", "read:tokens", "shares"
    jupyterhub_api_token: str = "token"
    # expected scope for getting tokens
    token_acquirer_scope: str = "custom:token-acquirer:read"
    # whether to release tokens when the server is already shared
    release_with_shared_server: bool = False
    # define a list of fields to be returned when getting the token details
    # if empty, everything will be returned
    token_info_fields: List[str] = []


settings = Settings()
app = FastAPI(root_path=settings.jupyterhub_service_prefix.rstrip("/"))

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()
logger.info(f"Targetting {settings.jupyterhub_api_url} as API URL")
logger.info(f"Service listening under {settings.jupyterhub_service_prefix}")


# mimic jupyterhub where errors are shown with "message"
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    message = str(exc.detail)
    try:
        err = json.loads(message)
        if isinstance(err, dict):
            message = err.get("message", message)
    except json.decoder.JSONDecodeError:
        pass
    return JSONResponse(status_code=exc.status_code, content={"message": message})


def get_user_token(request: Request):
    if settings.auth_header not in request.headers:
        raise HTTPException(status_code=401, detail="Missing authentication header")
    token_header = request.headers[settings.auth_header].split()
    if len(token_header) == 2 and token_header[0].lower() in settings.token_types:
        return token_header[1]
    raise HTTPException(status_code=401, detail="Missing authentication header")


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
        try:
            r.raise_for_status()
        except HTTPException:
            logger.debug(f"Error from upstream server {r.content}")
            raise HTTPException(r.status_code, detail=r.content.decode())
        try:
            return r.json()
        except ValueError:
            return r.content


async def get_user_data(request: Request):
    user_token = get_user_token(request)
    # Minimal user info from user_token
    user_info = await call_hub_api(path="user", token=user_token)
    token_info = await call_hub_api(
        path=f"users/{user_info['name']}/tokens/{user_info['token_id']}",
        token=settings.jupyterhub_api_token,
    )
    # More detailed user info
    user_info = await call_hub_api(
        # include_stopped_servers is url param for including stopped servers
        path=f"users/{user_info['name']}?include_stopped_servers",
        token=settings.jupyterhub_api_token,
    )

    oauth_client = token_info.get("oauth_client", "")
    session_id = token_info.get("session_id", None)

    logger.debug(
        f"User {token_info['user']} with session {session_id}"
        f" and oauth_client {oauth_client}"
    )

    if not (session_id and oauth_client) or oauth_client.lower().find("server at") < 0:
        raise HTTPException(403, detail="Forbidden, invalid token was used")

    server_name = None
    is_owner = False

    for server in user_info["servers"]:
        server_url_re = re.compile(
            rf"(?<=\W){re.escape(user_info['servers'][server]['url'])}(?=\W|$)"
        )
        # Checking if /user/{user_id}/{server_name}
        # corresponds with token oauth_client param
        re_match = server_url_re.search(oauth_client)

        if re_match is not None and re_match[0] == user_info["servers"][server]["url"]:
            server_name = user_info["servers"][server]["name"]
            is_owner = True
            break

    if not is_owner:
        raise HTTPException(
            403, detail="Forbidden, token owner does not match server owner"
        )

    return {
        "user_info": user_info,
        "user_token": user_token,
        "token_info": token_info,
        "server_name": server_name,
    }


async def server_has_shares(
    owner: str, server_name: Optional[str] = "", raise_exc: Optional[bool] = False
):
    shares = await call_hub_api(
        path=f"shares/{owner}/{server_name}",
        token=settings.jupyterhub_api_token,
    )
    result = bool(shares.get("items", []))
    if raise_exc and result:
        raise HTTPException(403, detail="Forbidden, server is shared")
    return result


async def server_has_share_codes(
    owner: str, server_name: Optional[str] = "", raise_exc: Optional[bool] = False
):
    share_codes = await call_hub_api(
        path=f"share-codes/{owner}/{server_name}",
        token=settings.jupyterhub_api_token,
    )
    result = bool(share_codes.get("items", []))
    if raise_exc and result:
        # Using "share link" term here for better clarity for users
        raise HTTPException(403, detail="Forbidden, share links exist for the server")
    return result


async def is_server_shared(owner: str, server_name: Optional[str] = ""):
    return await server_has_share_codes(
        owner, server_name, False
    ) or await server_has_shares(owner, server_name, False)


async def fail_if_shared_server(owner: str, server_name: Optional[str] = ""):
    await server_has_share_codes(owner, server_name, True)
    await server_has_shares(owner, server_name, True)


@app.get("/token_details")
async def get_token_details(request: Request):
    """Gets access token details."""
    logger.debug("Get token details request")
    user_data = await get_user_data(request)

    if not settings.release_with_shared_server:
        await fail_if_shared_server(
            user_data["user_info"]["name"], user_data["server_name"]
        )
    oauth_user = user_data["user_info"].get("auth_state", {}).get("oauth_user", {})
    if not oauth_user:
        raise HTTPException(404, detail="No user data available")
    if settings.token_info_fields:
        return {k: v for k, v in oauth_user.items() if k in settings.token_info_fields}
    return oauth_user


@app.get("/token")
async def get_token(request: Request):
    """Gets access token from the auth_state.

    It will return the access token if:
    1. the calling token owner is the same as the server owner
    2. the calling token has the scope configured in `token_acquirer_scope`
    3. the calling token is associated to a running server
    """
    logger.debug("Get token request")
    user_data = await get_user_data(request)

    if settings.token_acquirer_scope not in user_data["token_info"]["scopes"]:
        raise HTTPException(
            403, detail=f"Forbidden, requires {settings.token_acquirer_scope} scope"
        )
    if user_data["server_name"] is None:
        raise HTTPException(403, detail="Forbidden, no server token")
    if not settings.release_with_shared_server:
        await fail_if_shared_server(
            user_data["user_info"]["name"], user_data["server_name"]
        )

    access_token = None
    auth_state = user_data["user_info"].get("auth_state", {})
    if auth_state:
        access_token = auth_state.get("access_token", None)
    if not access_token:
        raise HTTPException(404, detail="No access token available for the user")
    return {"access_token": access_token}


async def call_wrapper(request: Request, path: str):
    """Wraps calls the the HUP API using our token"""
    logger.debug(f"Wrapping call to {path}")
    # Does owner verification
    await get_user_data(request)
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
    user_data = await get_user_data(request)
    if not await is_server_shared(owner, user_data["server_name"]):
        # First revoke the token as the server is shared
        hub_url = settings.jupyterhub_api_url.rstrip("/").removesuffix("/api")
        await call_hub_api(
            path=settings.token_revoke_path,
            base_url=hub_url,
            method="post",
            token=user_data["user_token"],
        )
    # 2. Then create sharing - just redirect the call
    resp = await call_hub_api(
        path=f"share-codes/{owner}/{server_name}",
        method="post",
        content=await request.body(),
        headers=dict(request.headers),
        token=settings.jupyterhub_api_token,
    )
    return resp


@app.get("/share-codes/{svc_path:path}")
@app.delete("/share-codes/{svc_path:path}")
async def share_codes_calls(request: Request, svc_path: str):
    return await call_wrapper(request, f"share-codes/{svc_path}")


@app.get("/shares/{svc_path:path}")
@app.patch("/shares/{svc_path:path}")
@app.delete("/shares/{svc_path:path}")
async def wrap_shares(request: Request, svc_path: str):
    return await call_wrapper(request, f"shares/{svc_path}")
