from libinjection import *
import sys

astr = sys.argv[1]
s = sqli_state()
sqli_init(s, astr, 0)
astr = None
issqli = is_sqli(s)
print(issqli)
