from soc_toolkit.utils.validators import IOCType, detect_ioc_type, extract_domain_from_url


def test_detect_ipv4():
    assert detect_ioc_type("8.8.8.8") == IOCType.IPV4


def test_detect_ipv6():
    assert detect_ioc_type("2001:4860:4860::8888") == IOCType.IPV6


def test_detect_domain():
    assert detect_ioc_type("example.com") == IOCType.DOMAIN


def test_detect_url():
    assert detect_ioc_type("http://example.com/path?x=1") == IOCType.URL


def test_detect_md5():
    assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == IOCType.MD5


def test_detect_sha1():
    assert detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == IOCType.SHA1


def test_detect_sha256():
    assert detect_ioc_type(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"[:64]
    ) == IOCType.SHA256


def test_detect_email():
    assert detect_ioc_type("analyst@example.com") == IOCType.EMAIL


def test_detect_unknown():
    assert detect_ioc_type("!!! not an ioc ???") == IOCType.UNKNOWN


def test_extract_domain_from_url():
    assert extract_domain_from_url("http://sub.example.co.uk/path") == "example.co.uk"
