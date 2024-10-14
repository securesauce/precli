# level: NONE
def test_foobar(a: str = None):
    assert a is not None
    return f"Hello {a}"


foobar(None)
