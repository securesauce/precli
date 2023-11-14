# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 37
# end_column: 42
from cryptography.hazmat.primitives.asymmetric import ec


private_value = 0x63BD3B01C5CE749D87F5F7481232A93540ACDB0F7B5C014ECD9CD3
curve = ec.SECT163R2
ec.derive_private_key(private_value, curve)
