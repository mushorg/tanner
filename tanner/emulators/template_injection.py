import asyncio
import logging
import tornado

from tanner.utils import patterns
from tornado.template import Template
from mako.template import Template
from jinja2 import Environment

Jinja2 = Environment()


class TemplateInjection:
    """
        This emulator covers Jinja2, Mako and Tornado template engines.
    """

    def __init__(self, loop=None):
        self._loop = loop if loop is not None else asyncio.get_event_loop()
        self.logger = logging.getLogger('tanner.template_injection')

    def get_injection_result(self, payload):

        template_injection_result = None
        base_template = """<html><head><title>Welcome %s !!</title></head></html>""" % payload

        if patterns.TEMPLATE_INJECTION_MAKO.match(payload):
            mako_template = Template(base_template)
            template_injection_result = mako_template.render()

        elif patterns.TEMPLATE_INJECTION_JINJA2.match(payload):
            template_injection_result = Jinja2.from_string(base_template).render()

        elif patterns.TEMPLATE_INJECTION_TORNADO.match(payload):
            result = tornado.template.Template(base_template)
            template_injection_result = result.generate()

        return template_injection_result

    def scan(self, value):
        detection = None

        if patterns.TEMPLATE_INJECTION_JINJA2.match(value) or patterns.TEMPLATE_INJECTION_MAKO.match(value) or \
                patterns.TEMPLATE_INJECTION_TORNADO.match(value):
            detection = dict(name='template_injection', order=3)
        return detection

    async def handle(self, attack_params):
        result = self.get_injection_result(attack_params[0]['value'])

        return dict(value=result, page=False)
