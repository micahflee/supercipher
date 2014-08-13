from nose import with_setup
from supercipher.scfile import *

def test_scfile_version_to_bytes():
    "SuperCipherFile.version_to_bytes should convert the version to 3 bytes"
    scf = SuperCipherFile('1.1.1')
    assert scf.version_to_bytes('1.5.9') == '\x01\x05\x09'
    assert scf.version_to_bytes('0.0.3') == '\x00\x00\x03'
    assert scf.version_to_bytes('255.255.255') == '\xff\xff\xff'

def test_scfile_bytes_to_version():
    "SuperCipherFile.bytes_to_version should convert 3 bytes to a version string"
    scf = SuperCipherFile('1.1.1')
    assert scf.bytes_to_version('\x01\x05\x09') == '1.5.9'
    assert scf.bytes_to_version('\x00\x00\x03') == '0.0.3'
    assert scf.bytes_to_version('\xff\xff\xff') == '255.255.255'

