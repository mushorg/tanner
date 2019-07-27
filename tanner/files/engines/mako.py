from mako.template import Template
mako_template = Template("""%s""")
template_injection_result = mako_template.render()
print(template_injection_result)
