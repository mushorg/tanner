from tanner.utils import patterns


class XssEmulator:
    def scan(self, value):
        detection = None
        if patterns.XSS_ATTACK.match(value):
            detection = dict(name="xss", order=3)
        return detection

    def get_xss_result(self, session, attack_params):
        result = None
        value = ""
        for param in attack_params:
            value += param["value"] if not value else "\n" + param["value"]
        result = dict(value=value, page=True)
        return result

    async def handle(self, attack_params, session):
        xss_result = None
        xss_result = self.get_xss_result(session, attack_params)
        return xss_result
