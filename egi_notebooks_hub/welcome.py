"""Handler for a simple welcome page for EGI Notebooks
"""

from jupyterhub.handlers.base import BaseHandler
from tornado.escape import url_escape
from tornado.httputil import url_concat


class WelcomeHandler(BaseHandler):
    """Render the welcome home page.

    For using it, define the following config:

    from egi_notebooks_hub.welcome import WelcomeHandler
    c.JupyterHub.default_url = "/welcome"
    c.JupyterHub.extra_handlers = [
         (r'/welcome', WelcomeHandler),
    ]
    c.Authenticator.auto_login = True


    """

    default_url = None  # Avoid redirect loop

    async def get(self):
        user = self.current_user
        if user:
            # we have a user, no need to welcome just go wherever it needs to go
            self.redirect(self.get_next_url(user))
            return

        # render the welcome page for not logged users
        # all options basically taken from
        # jupyterhub.handlers.login.LoginHandler
        html = await self.render_template(
            "welcome.html",
            next=url_escape(self.get_argument("next", default="")),
            custom_html=self.authenticator.custom_html,
            login_url=self.settings["login_url"],
            authenticator_login_url=url_concat(
                self.authenticator.login_url(self.hub.base_url),
                {"next": self.get_argument("next", "")},
            ),
        )
        self.finish(html)
