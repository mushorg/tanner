import logging
import re

from tanner.util import patterns

class CRLFEmulator:
    def __init__:
        self.logger = 

    def scan(self, value):
        detection = None
        if patterns.CRLF_ATTACK.match(value):
            detection = dict(name='crlf', order=2)
        return detection

    def get_crlf_results(self, attack_params):
        headers = {attack_param['id']: attack_value['value']}
        return headers

    async def handle(self, attack_params, session):
        result = self.get_crlf_results(attack_params)
        return dict(value='', page=True, headers=value)
