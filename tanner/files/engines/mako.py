from colorama import Back
from mako.template import Template
mako_template = Template("""{}""")
template_injection_result = mako_template.render()
print(Back.GREEN + template_injection_result)
