import mimetypes
import re
import urllib.parse

from tanner.utils import patterns


class XssEmulator:
    
    def scan(self, value):
        detection = None
        if patterns.XSS_ATTACK.match(value):
            detection = dict(name= 'cmd_exec', order= 3)
        return detection

    def get_xss_result(self, session, val):
        result = None
        injectable_page = None
        if session:
            injectable_page = self.set_xss_page(session)
        if injectable_page is None:
            injectable_page = '/index.html'
        if val:
            result = dict(value=val,
                          page=injectable_page)
        return result

    @staticmethod
    def set_xss_page(session):
        injectable_page = None
        for page in reversed(session.paths):
            if mimetypes.guess_type(page['path'])[0] == 'text/html':
                injectable_page = page['path']
        return injectable_page

    async def handle(self, attack_value, session):
        xss_result = None
        xss_result = self.get_xss_result(session, attack_value['value'])
        return xss_result
