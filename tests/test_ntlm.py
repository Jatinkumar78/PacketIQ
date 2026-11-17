"""
Tests for the shared NTLM identity extraction.

These live apart from the WinRM tests because NTLM rides SMB2 session setup
just as it rides a WinRM `Authorization` header, and the decoding is the same
either way. Both traps covered here were found by testing rather than by
reading the spec: scapy returns these names as bytes unless the client
negotiated Unicode, and it raises for a field the client omitted instead of
returning nothing.
"""

import base64

from scapy.layers.ntlm import NTLM_AUTHENTICATE_V2

from packetiq.detection import ntlm


def ntlm_authenticate(user="larry.doe", domain="directory.thm", workstation="KALI"):
    msg = NTLM_AUTHENTICATE_V2(UserName=user, DomainName=domain, Workstation=workstation)
    return base64.b64encode(bytes(msg)).decode("ascii")


def test_a_unicode_encoded_name_is_decoded_from_utf16():
    assert ntlm._name("larry.doe".encode("utf-16-le")) == "larry.doe"


def test_an_oem_encoded_name_is_decoded_as_plain_bytes():
    """A client that does not negotiate Unicode sends the name in OEM codepage."""
    assert ntlm._name(b"BACKUPSVC") == "BACKUPSVC"


def test_a_name_that_is_already_a_string_is_left_alone():
    assert ntlm._name("larry.doe") == "larry.doe"
    assert ntlm._name(None) == ""


def test_a_field_the_client_omitted_reads_as_empty_rather_than_raising():
    """scapy raises AttributeError for an absent NTLM field, not None.

    One `suppress` around all three reads therefore discarded a perfectly good
    username whenever the domain was missing, which is what a local or
    workgroup account looks like and precisely the account worth noticing.
    """
    class Missing:
        def __getattr__(self, name):
            raise AttributeError(name)

    class Awkward:
        """scapy's field accessor raises ValueError before it raises AttributeError.

        `getattr(obj, name, None)` absorbs only the AttributeError, so the
        ValueError has to be caught explicitly or it escapes mid-capture.
        """

        def __getattr__(self, name):
            raise ValueError(name)

    assert ntlm._field(Missing(), "DomainName") == ""
    assert ntlm._field(Awkward(), "DomainName") == ""


