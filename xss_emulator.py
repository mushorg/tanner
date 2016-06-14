import asyncio
import urllib.parse
import re
import mimetypes


class XssEmulator:
    def extract_xss_data(self, data):
        value = ''
        if 'post_data' in data:
            for field, val in data['post_data'].items():
                val = urllib.parse.unquote(val)
                xss = re.match(r'.*<(.*)>.*', val)
                if xss:
                    value += val if not value else '\n'+val
        return value

    def get_xss_result(self, session, val):
        result = None
        injectable_page = '/index.html'
        if session:
            injectable_page = self.set_xss_page(session)
        if val:
            result = dict(name='xss', value=val,
                          page=injectable_page)
        return result

    def set_xss_page(self, session):
        for page in reversed(session.paths):
            if mimetypes.guess_type(page['path'])[0] == 'text/html':
                injectable_page = page['path']
                return injectable_page

    def handle(self, session, value, raw_data=None):
        xss_result = None
        if not value:
            value = self.extract_xss_data(raw_data)
        xss_result = self.get_xss_result(session, value)
        return xss_result
