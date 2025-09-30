"""
A simple service to get a valid access token for the current user.
"""

import json
import os
from urllib.parse import urlparse

from jupyterhub.services.auth import HubAuthenticated
from jupyterhub.utils import url_path_join
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.web import Application, HTTPError, RequestHandler, authenticated


class TokenAcquirerHandler(HubAuthenticated, RequestHandler):
    """Gets tokens from the auth_state.

    It requires the service to be configured with the right scopes:
    `read:users` and `admin:auth_state`.

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
             "scopes": ["read:users", "admin:auth_state"],
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

    @authenticated
    def get(self):
        user_model = self.get_current_user()
        sync = True
        data = self.hub_auth._call_coroutine(
            sync,
            self.hub_auth._api_request,
            "GET",
            url=url_path_join(
                self.hub_auth.api_url,
                "users",
                user_model["name"],
            ),
            headers={"Authorization": "token " + self.hub_auth.api_token},
        )
        # self.logger.debug(f"Getting token for {user_model['name']}")
        access_token = data.get("auth_state", {}).get("access_token", None)
        if not access_token:
            raise HTTPError(404, reason="No access token available for the user")
        self.set_header("content-type", "application/json")
        self.write(json.dumps({"access_token": access_token}))


def main():
    app = Application(
        [
            (os.environ["JUPYTERHUB_SERVICE_PREFIX"] + "/?", TokenAcquirerHandler),
            (r".*", TokenAcquirerHandler),
        ]
    )
    http_server = HTTPServer(app)
    url = urlparse(os.environ["JUPYTERHUB_SERVICE_URL"])
    http_server.listen(url.port, url.hostname)
    IOLoop.current().start()


if __name__ == "__main__":
    main()
