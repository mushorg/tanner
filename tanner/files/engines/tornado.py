import tornado
from colorama import Fore,init
init(autoreset=True)
from tornado.template import Template
code = "{}"
result = tornado.template.Template(code)
template_injection_result = result.generate()
print(Fore.GREEN + template_injection_result)
