from enum import Enum, unique


@unique
class AttackType(Enum):
    unknown = 0
    rfi = 1
    lfi = 2
    xss = 3
    sqli = 4
    crlf = 5
    index = 6
    cmd_exec = 7
    xxe_injection = 8
    php_code_injection = 9
    template_injection = 10
    php_object_injection = 11
