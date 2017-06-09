import mimetypes
import re
import urllib.parse

from tanner.utils import patterns


class XssEmulator:
    
    def scan(self, value):
        detection = None
        if patterns.XSS_ATTACK.match(value):
            detection = dict(name= 'xss', order= 3)
        return detection

    def get_xss_result(self, session, attack_params):
        result = None
        injectable_page = None
        value = ''
        if session:
            injectable_page = self.set_xss_page(session)
        if injectable_page is None:
            injectable_page = '/index.html'
        for param in attack_params:
            value += param['value'] if not value else '\n' + param['value']
        result = dict(value=value,
                      page=injectable_page)
        return result

    @staticmethod
    def set_xss_page(session):
        injectable_page = None
        for page in reversed(session.paths):
            if mimetypes.guess_type(page['path'])[0] == 'text/html':
                injectable_page = page['path']
        return injectable_page

    async def handle(self, attack_params, session):
        xss_result = None
        xss_result = self.get_xss_result(session, attack_params)
        return xss_result
