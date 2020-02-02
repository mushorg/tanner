import tornado
from colorama import Back
from tornado.template import Template
code = "{}"
result = tornado.template.Template(code)
template_injection_result = result.generate()
print(Back.GREEN + template_injection_result)
