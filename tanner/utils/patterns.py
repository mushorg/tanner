import re

INDEX = re.compile(r"(/index.html|/)")
RFI_ATTACK = re.compile(r".*((http(s){0,1}|ftp(s){0,1}):).*", re.IGNORECASE)
LFI_ATTACK = re.compile(r".*(/\.\.)*(home|proc|usr|etc)/.*")
LFI_FILEPATH = re.compile(r"((\.\.|/).*)")
CMD_ATTACK = re.compile(
    r".*[^A-z:./]"
    r"(alias|cat|cd|cp|echo|exec|find|for|grep|ifconfig|ls|man|mkdir|netstat|ping|ps|pwd|uname|wget|touch|while)"
    r"([^A-z:./]|\b)"
)
PHP_CODE_INJECTION = re.compile(r".*(;)*(echo|system|print|phpinfo)(\(.*\)).*")
PHP_OBJECT_INJECTION = re.compile(r"(^|;|{|})O:[0-9]+:")
CRLF_ATTACK = re.compile(r".*(\r\n).*")
XXE_INJECTION = re.compile(r".*<(\?xml|(!DOCTYPE.*)).*>")
TEMPLATE_INJECTION_MAKO = re.compile(r".*(<%.*|\s%>).*")
TEMPLATE_INJECTION_TORNADO = re.compile(r".*({{.*}}).*")
XSS_ATTACK = re.compile(r".*<(.|\n)*?>")
REMOTE_FILE_URL = re.compile(r"(.*(http(s){0,1}|ftp(s){0,1}):.*)")
WORD_PRESS_CONTENT = re.compile(r"/wp-content/.*")
HTML_TAGS = re.compile(r".*<(.*)>.*")
QUERY = re.compile(r".*\?.*=")
