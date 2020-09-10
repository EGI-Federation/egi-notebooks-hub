"""D4Science Authenticator for JupyterHub
"""

import base64
import datetime
import hashlib
import json
import os
from xml.etree import ElementTree

from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPError, HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import Authenticator, LocalAuthenticator
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join


D4SCIENCE_SOCIAL_URL = (os.environ.get('D4SCIENCE_SOCIAL_URL') or
                        'https://socialnetworking1.d4science.org/'
                        'social-networking-library-ws/rest/')
D4SCIENCE_PROFILE= '2/people/profile'

D4SCIENCE_DM_REGISTRY_URL = (os.environ.get('D4SCIENCE_REGISTRY_URL') or
                             'https://registry.d4science.org/icproxy/gcube/'
                             'service/ServiceEndpoint/DataAnalysis/DataMiner')


class D4ScienceLoginHandler(BaseHandler):
    # override implementation of clear_cookies from tornado to add extra options
    def clear_cookie(self, name, path="/", domain=None):
        kwargs = self.settings.get('cookie_options', {})
        expires = datetime.datetime.utcnow() - datetime.timedelta(days=365)
        self.set_cookie(name, value="", path=path, expires=expires, domain=domain, **kwargs)

    @gen.coroutine
    def get(self):
        self.log.debug('Authenticating user')
        user = yield self.get_current_user()
        token = self.get_argument('gcube-token')
        if user and token:
            self.log.info('Clearing login cookie, new user?')
            # clear login cookies with full set of options

            self.clear_login_cookie()
            # make sure we don't do a mess here
            self.redirect(url_concat(
                    self.authenticator.login_url(self.hub.base_url),
                    {'gcube-token': token}),
                permanent=False)
            return
        if not token:
            self.log.error('No gcube token. Out!')
            raise web.HTTPError(403)
        http_client = AsyncHTTPClient()
        # discover user info
        user_url = url_concat(url_path_join(D4SCIENCE_SOCIAL_URL,
                                            D4SCIENCE_PROFILE),
                              {'gcube-token': token})
        req = HTTPRequest(user_url, method='GET')
        try:
            resp = yield http_client.fetch(req)
        except HTTPError as e:
            # whatever, get out
            self.log.warning('Something happened with gcube service: %s', e)
            raise web.HTTPError(403)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        username = resp_json.get('result', {}).get('username', '')
        if not username:
            self.log.error('Unable to get the user from gcube?')
            raise web.HTTPError(403)

        # discover WPS
        self.log.info('Discover wps')
        wps_endpoint = ''
        discovery_url = url_concat(D4SCIENCE_DM_REGISTRY_URL,
                                   {'gcube-token': token})
        req = HTTPRequest(discovery_url, method='GET')
        try:
            self.log.info('fetch')
            resp = yield http_client.fetch(req)
        except HTTPError as e:
            # whatever, get out
            self.log.warning('Something happened with gcube service: %s', e)
            raise web.HTTPError(403)
        root = ElementTree.fromstring(resp.body.decode('utf8', 'replace'))
        self.log.info('root %s', root)
        for child in root.findall('Resource/Profile/AccessPoint/'
                                  'Interface/Endpoint'):
            entry_name = child.attrib["EntryName"]
            self.log.info('entry_name %s', entry_name)
            if entry_name != "GetCapabilities":
                wps_endpoint = child.text
                self.log.info('WPS endpoint: %s', wps_endpoint)
                break

        self.log.info('D4Science user is %s', username)
        self.log.info('WPS %s', wps_endpoint)
        data = {'gcube-token': token, 'gcube-user': username,
                'wps-endpoint': wps_endpoint}
        data.update(resp_json['result'])
        user = yield self.login_user(data)
        if user:
            self._jupyterhub_user = user
            self.redirect(self.get_next_url(user), permanent=False)


class D4ScienceAuthenticator(Authenticator):
    login_handler = D4ScienceLoginHandler
    auto_login = True

    @gen.coroutine
    def authenticate(self, handler, data=None):
        if data and data.get('gcube-user'):
            return {'name': data['gcube-user'],
                    'auth_state': data}
        return None

    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        """Pass gcube-token to spawner via environment variable"""
        auth_state = yield user.get_auth_state()
        if not auth_state:
            # auth_state not enabled
            return
        spawner.environment['GCUBE_TOKEN'] = auth_state['gcube-token']
        spawner.environment['DATAMINER_URL'] = auth_state['wps-endpoint']

    def get_handlers(self, app):
        return([(r'/login', self.login_handler)])
