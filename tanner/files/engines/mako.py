from colorama import Fore,init
init(autoreset=True)
from mako.template import Template
mako_template = Template("""{}""")
template_injection_result = mako_template.render()
print(Fore.GREEN + template_injection_result)
