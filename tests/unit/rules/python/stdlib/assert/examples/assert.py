# level: WARNING
# start_line: 7
# end_line: 7
# start_column: 4
# end_column: 10
def foobar(a: str = None):
    assert a is not None
    return f"Hello {a}"


foobar(None)
