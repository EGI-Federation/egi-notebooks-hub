import logging
from typing import List

import httpx
from fastapi import FastAPI, HTTPException, Request
from jupyterhub.utils import url_path_join
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    auth_header: str = "authorization"
    token_types: List[str] = ["bearer", "token"]
    jupyterhub_service_prefix: str = "/services/share-manager"
    jupyterhub_api_url: str = "http://localhost:8000/hub/api"
    jupyterhub_url: str = "http://localhost:8000/hub"
    api_timeout: float = 15.0
    api_token: str = "token"
    token_acquirer_scope: str = "custom:token-acquirer:read"


settings = Settings()
app = FastAPI(root_path=settings.jupyterhub_service_prefix)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()
logger.info(f"Targetting {settings.jupyterhub_api_url} as API URL")
logger.info(f"Service listening under {settings.jupyterhub_service_prefix}")


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
        logger.debug(f"Server name is `{server_name}`")
        return server_path[-1]
    return None


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


@app.get("/token")
async def get_token(request: Request):
    """Gets tokens from the auth_state.

    It requires the service to be configured with the right scopes:
    `read:users`, `admin:auth_state` and `read:tokens`.

     Sample configuration:
     ```
     c.JupyterHub.load_roles = [
         {
             'name': 'user',
             'description': 'Grant users access to hub services',
             'scopes': ["access:services", "self"],
         },
         {
             "name": "token-aquirer",
             "scopes": ["read:users", "admin:auth_state", "read:tokens"],
             "services": ["token-acquirer"]
         }
     ]

     c.JupyterHub.services = [
         {
             'name': 'token-acquirer',
             'command': ['python3', '-m', 'egi_notebooks_hub.services.token_acquirer'],
             # the service will listen on whatever is configured here
             'url': 'http://127.0.0.1:8090',
         }
     ]
     ```
    """
    logger.debug("Get token called")
    user_token = get_user_token(request)

    # get the token info
    user_info = await call_hub_api(path="user", token=user_token)
    token_info = await call_hub_api(
        path=f"users/{user_info['name']}/tokens/{user_info['token_id']}",
        token=user_token,
    )
    if settings.token_acquirer_scope not in token_info["scopes"]:
        raise HTTPException(
            403, detail=f"Forbidden, requires {settings.token_acquirer_scope} scope!"
        )
    server_name = get_server_name(token_info)
    if not server_name:
        raise HTTPException(403, detail="Forbidden, no server token!")
    shares = await call_hub_api(
        path=f"shares/{user_info['name']}/{server_name}",
        token=user_token,
    )
    if shares.get("items", []):
        raise HTTPException(403, detail="Forbidden, server is shared!")
    user_data = await call_hub_api(
        path=f"users/{user_info['name']}",
        token=settings.api_token,
    )
    access_token = None
    auth_state = user_data.get("auth_state", {})
    if auth_state:
        access_token = auth_state.get("access_token", None)
    if not access_token:
        raise HTTPException(404, detail="No access token available for the user")
    return {"access_token": access_token}


@app.post("/share-codes/{owner:str}/{server_name:str}")
async def create_share_code(request: Request, owner: str, server_name: str):
    logger.debug("Share code post called")
    user_token = get_user_token(request)
    shares = await call_hub_api(
        path=f"shares/{owner}/{server_name}",
        token=user_token,
    )
    if not shares.get("items", []):
        # First revoke the token as the server is shared
        await call_hub_api(
            path="token_revoke",
            base_url=settings.jupyterhub_url,
            method="post",
            token=user_token,
        )
    # 2. Then create sharing - just redirect the call
    resp = await call_hub_api(
        path=f"/share-codes/{owner}/{server_name}",
        method="post",
        content=await request.body(),
        headers=dict(request.headers),
        token=settings.api_token,
    )
    return resp


async def call_wrapper(request: Request, path: str):
    logger.debug(f"Wrapping call to {path}")
    resp = await call_hub_api(
        path=path,
        method=request.method.lower(),
        content=await request.body(),
        headers=dict(request.headers),
        token=settings.api_token,
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
