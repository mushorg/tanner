import asyncio
import urllib.parse
import re
import mimetypes


class XSSemulator:
    def extract_xss_data(self, data):
        xss = None
        if 'post_data' in data:
            for field, val in data['post_data'].items():
                val = urllib.parse.unquote(val)
                xss = re.match(r'.*<(.*)>.*', val)
                if xss:
                    return val


    def create_xss_response(self, session, val):
        injectable_page = '/index.html'
        for page in reversed(session.paths):
            if mimetypes.guess_type(page['path'])[0] == 'text/html':
                injectable_page = page['path']
        detection = dict(
            name='xss',
            order='2',
            payload=dict(name='xss', value=val,
                         page=injectable_page)
        )

        return detection
