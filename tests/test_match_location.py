import pytest
from hexpose.match_location import MatchLocation, locate_match, locate_all


DATA = b"line one\nline two\nline three\n"


def test_locate_start_of_file():
    loc = locate_match(DATA, 0)
    assert loc.line_number == 1
    assert loc.column == 0
    assert loc.offset == 0


def test_locate_within_first_line():
    loc = locate_match(DATA, 5)
    assert loc.line_number == 1
    assert loc.column == 5


def test_locate_second_line():
    # "line two" starts at offset 9
    loc = locate_match(DATA, 9)
    assert loc.line_number == 2
    assert loc.column == 0


def test_locate_mid_second_line():
    loc = locate_match(DATA, 14)
    assert loc.line_number == 2
    assert loc.column == 5


def test_locate_third_line():
    # "line three" starts at offset 18
    loc = locate_match(DATA, 18)
    assert loc.line_number == 3
    assert loc.column == 0


def test_locate_empty_data():
    loc = locate_match(b"", 0)
    assert loc.line_number == 1
    assert loc.column == 0


def test_source_path_stored():
    loc = locate_match(DATA, 0, source_path="/tmp/dump.bin")
    assert loc.source_path == "/tmp/dump.bin"


def test_as_dict_keys():
    loc = locate_match(DATA, 9, source_path="a.bin")
    d = loc.as_dict()
    assert set(d.keys()) == {"offset", "line_number", "column", "source_path"}
    assert d["offset"] == 9


def test_str_representation():
    loc = MatchLocation(offset=9, line_number=2, column=0, source_path="x.bin")
    s = str(loc)
    assert "x.bin" in s
    assert "2" in s


def test_locate_all_returns_list():
    locs = locate_all(DATA, [0, 9, 18])
    assert len(locs) == 3
    assert locs[0].line_number == 1
    assert locs[1].line_number == 2
    assert locs[2].line_number == 3


def test_locate_all_empty_offsets():
    locs = locate_all(DATA, [])
    assert locs == []
