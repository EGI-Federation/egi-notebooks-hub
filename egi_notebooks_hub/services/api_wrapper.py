import logging
import os.path

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    auth_header: str = "authorization"
    token_type: str = "bearer"
    jupyterhub_service_prefix: str = "/services/jwt"
    jupyterhub_api_url: str = "http://localhost:8000/hub/api"
    jwt_login_suffix: str = "/jwt_login"


settings = Settings()
app = FastAPI()
logger = logging.getLogger("uvicorn.error")

logger.info(f"Targetting {settings.jupyterhub_api_url} as API URL")
logger.info(f"Service listening under {settings.jupyterhub_service_prefix}")


# wrapping all the HTTP actions in a single function
@app.get("{svc_path:path}")
@app.put("{svc_path:path}")
@app.post("{svc_path:path}")
@app.delete("{svc_path:path}")
@app.options("{svc_path:path}")
@app.head("{svc_path:path}")
@app.patch("{svc_path:path}")
@app.trace("{svc_path:path}")
async def api_wrapper(request: Request, svc_path: str):
    token_header = {}
    logger.debug(f"API Call to {svc_path}")
    # we are guessing the login URL as we don't have the HUB URL directly on env
    # should this be explicitly configured?
    login_url = (
        settings.jupyterhub_api_url.removesuffix("/api") + settings.jwt_login_suffix
    )
    if settings.auth_header in request.headers:
        f = request.headers[settings.auth_header].split()
        if len(f) == 2 and f[0].lower() == settings.token_type:
            try:
                async with httpx.AsyncClient() as client:
                    headers = {
                        settings.auth_header: request.headers[settings.auth_header]
                    }
                    r = await client.get(login_url, headers=headers)
                    r.raise_for_status()
                    user_token = r.json()
                    token_header[settings.auth_header] = f"token {user_token['token']}"
            except httpx.HTTPStatusError as exc:
                logger.debug("Failed auth, may still work!")
                if exc.response.status_code != 403:
                    raise HTTPException(
                        status_code=exc.response.status_code, detail=exc.response.text
                    )
    content = await request.body()
    api_path = (
        svc_path.removeprefix(settings.jupyterhub_service_prefix.rstrip("/"))
        if svc_path
        else ""
    )
    async with httpx.AsyncClient() as client:
        # which headers do we need to preserve?
        headers = dict(request.headers)
        if settings.auth_header in headers:
            del headers[settings.auth_header]
        headers.update(token_header)
        method = getattr(client, request.method.lower())
        target_url = os.path.join(
            settings.jupyterhub_api_url, api_path.removeprefix("/")
        )
        logger.info(f"Target API call: {target_url}")
        if content:
            r = await method(target_url, content=content, headers=headers)
        else:
            r = await method(target_url, headers=headers)
        try:
            return r.json()
        except ValueError:
            return r.content
