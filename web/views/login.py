# coding: utf-8
#

from logzero import logger

from .auth import AuthError, OpenIdMixin
from .base import BaseRequestHandler
from .cas_login import get_key, login, validate

from ..settings import AUTH_BACKENDS


class OpenIdLoginHandler(BaseRequestHandler, OpenIdMixin):
    _OPENID_ENDPOINT = AUTH_BACKENDS['openid']['endpoint']

    async def get(self):
        if self.get_argument("openid.mode", False):
            try:
                user = await self.get_authenticated_user()
            except AuthError as e:
                self.write(
                    "<code>Auth error: {}</code> <a href='/login'>Login</a>".
                    format(e))
            else:
                logger.info("User info: %s", user)
                await self.set_current_user(user['email'], user['name'])
                next_url = self.get_argument('next', '/')
                self.redirect(next_url)
        else:
            self.authenticate_redirect()


import time
class SimpleLoginHandler(BaseRequestHandler):
    def get(self):
        #self.set_cookie("next", self.get_argument("next", "/"))
        self.write('<html><body><form action="/login" method="post">'
                   'Name: <input type="text" name="name" required>'
                   'password: <input type="password" name="password" required>'
                   '<input type="submit" value="Sign in">'
                   '</form></body></html>')

    async def post(self):
        name = self.get_argument("name")
        pwd = self.get_argument("password")
        kid, pkey=get_key()
        device=int(time.time())
        login_param={
        'appName': 'CAS',  # 系统编码
        'username': name,  # 用户名
        'password': pwd,  # 密码
        'device': device,  # 不确定可以填写时间戳
        }
        log_param=login_param
        tgt=login(kid, pkey, log_param)
        resp=validate(tgt)
        if(resp['status']){
            email=name + "@anonymous.com"
            await self.set_current_user(email, name)
            next_url=self.get_cookie("next", "/")
            self.clear_cookie("next")
            self.redirect(next_url)
        }
        
        
