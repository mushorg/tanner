from tanner.utils import patterns


class PadOracleEmulator:

    def scan(self, value):
        detection = None
        if patterns.PAD_ORACLE_ATTACK.match(value):
            detection = dict(name='pad_oracle', order=2)
        return detection

    def get_pad_oracle_results(self, attack_params):
        headers = {attack_params[0]['id']: attack_params[0]['value']}
        return headers

    async def handle(self, attack_params, session):
        result = self.get_pad_oracle_results(attack_params)
        return dict(value='', page=True, headers=result)
