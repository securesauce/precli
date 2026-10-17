# level: ERROR
# start_line: 17
# end_line: 17
# start_column: 12
# end_column: 51
import hashlib


algorithms = {
    "weak": {
        "weaker": {
            "weakest": "md5",
        },
    },
    "secure": "sha256",
}
hashlib.new(algorithms["weak"]["weaker"]["weakest"])
