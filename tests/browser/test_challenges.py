import base64

import pytest

from browser_worker.challenges import Totp
from browser_worker.errors import BrowserFailure


@pytest.mark.parametrize("time_value,sha1,sha256,sha512", [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
])
def test_rfc6238_vectors(time_value, sha1, sha256, sha512):
    # RFC 6238 Appendix B's public interoperability vectors.
    for algorithm, size, expected in [("SHA1", 20, sha1), ("SHA256", 32, sha256), ("SHA512", 64, sha512)]:
        raw = (b"1234567890" * 7)[:size]
        seed = base64.b32encode(raw).decode().rstrip("=")
        totp = Totp.parse(f"otpauth://totp/Synthetic?secret={seed}&algorithm={algorithm}&digits=8&period=30")
        assert totp.code(now=time_value) == expected
        assert seed not in repr(totp) and raw.decode() not in str(totp)


@pytest.mark.parametrize("value", [
    "", "short", "otpauth://hotp/Synthetic?secret=JBSWY3DPEHPK3PXP&counter=1",
    "otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP&secret=AAAAAAAAAAAAAAAA",
    "otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
    "otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP&digits=4",
    "otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP&period=0",
    "otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP&callback=https://evil.invalid",
    "otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP#fragment",
])
def test_unsupported_totp_parameters_are_fixed_failures(value):
    with pytest.raises(BrowserFailure, match="unsupported_challenge"):
        Totp.parse(value)


def test_raw_seed_defaults_and_invalid_clock():
    seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert Totp.parse(seed).code(now=59) == "287082"
    for now in [-1, True, float("nan"), float("inf")]:
        with pytest.raises(BrowserFailure, match="unsupported_challenge"):
            Totp.parse(seed).code(now=now)
