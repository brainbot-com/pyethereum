#! /usr/bin/env py.test

import pytest
from pyethereum.rlp import encode, decode
from pyethereum.utils import int_to_big_endian


@pytest.fixture(params=["", "src", "a" * 55, "\0" * 55, "a" * 54, chr(0x80), chr(0x81), chr(0xff)])
def short_string(request):
    return request.param


# demonstrate another way to parametrize test functions
def pytest_generate_tests(metafunc):
    if "long_string" in metafunc.fixturenames:
        metafunc.parametrize("long_string", ['a' * 56, 'a' * 1024])
    if "small_byte" in metafunc.fixturenames:
        metafunc.parametrize("small_byte", [chr(x) for x in range(0x80)], ids=["chr(%s)" % x for x in range(0x80)])
    if "short_list" in metafunc.fixturenames:
        metafunc.parametrize("short_list", [
            [],
            ['foo', 'bar'],
            ['a', 'b', 'c'],
            ['a'] * 55])
    if "long_list" in metafunc.fixturenames:
        metafunc.parametrize("long_list", [
            [str(x) for x in range(100)],
            ['a'] * 56,
            ['a'] * 1024])


@pytest.fixture
def encoded_long_string(request, long_string):
    return encode(long_string)


def test_encode_decode_low_byte(small_byte):
    assert encode(small_byte) == small_byte
    assert decode(small_byte) == small_byte


def test_first_byte_short_string(short_string):
    enc = encode(short_string)
    assert ord(enc[0]) == 0x80 + len(short_string)
    assert enc[1:] == short_string
    assert decode(enc) == short_string


def test_encode_decode_long_string(encoded_long_string, long_string):
    length_bin = int_to_big_endian(len(long_string))
    assert encoded_long_string[0] == chr(0xb7 + len(length_bin))
    assert encoded_long_string[1:1 + len(length_bin)] == length_bin
    assert encoded_long_string[1 + len(length_bin):] == long_string
    assert decode(encoded_long_string) == long_string


def test_encode_decode_short_list(short_list):
    enc = encode(short_list)
    payload = "".join([encode(x) for x in short_list])
    assert ord(enc[0]) == 0xc0 + len(payload)
    assert enc[1:] == payload
    assert decode(enc) == short_list


def test_encode_decode_long_list(long_list):
    enc = encode(long_list)
    payload = "".join([encode(x) for x in long_list])
    length_bin = int_to_big_endian(len(payload))

    assert ord(enc[0]) == 0xf7 + len(length_bin)
    assert enc[1:1 + len(length_bin)] == length_bin
    assert enc[1 + len(length_bin):] == payload


# another way to parametrize test functions
@pytest.mark.parametrize("bad", [
    ([0.0],),
    ([0],),
    ([1],),
    ([None],),
    ([1, 'ok'],),
    ([None, 'ok'],),
    ([[1], 'ok'],)])
def test_encode_raise_type_error(bad):
    """test that encode raises type error on unknown types"""
    with pytest.raises(TypeError):
        encode(bad)
