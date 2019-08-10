import tornado
from tornado.template import Template
code = "{}"
result = tornado.template.Template(code)
template_injection_result = result.generate()
print(template_injection_result)
