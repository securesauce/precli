# level: NONE
import re

IPv6address = r"([A-Fa-f0-9:]+[:$])[A-Fa-f0-9]{1,4}"
reg = re.compile(IPv6address)
reg.search("http://[:::::::::::::::::::::::::::::::::::::::]/path")
