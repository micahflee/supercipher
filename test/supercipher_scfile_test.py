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

def test_scfile_load_small_file():
    "SuperCipher files should all be at least 24 bytes"

def test_scfile_load_wrong_magic_number():
    "SuperCipher files should begin with the magic number 0xEBA34B1C"

def test_scfile_load_future_version():
    "should throw error if loading a SuperCipher file from a future version"

def test_scfile_decrypt_before_loading():
    "you must run SuperCipherFile.load before .decrypt"

def test_scfile_decrypt_invalid_archive():
    "the .tar.gz inside a SuperCipher file must be a valid one"

def test_scfile_encryption():
    "should be able to encrypt/decrypt successfully"

def test_scfile_encryption_pubkey():
    "should be able to encrypt/decrypt successfully with a valid pubkey and seckey"

def test_scfile_encryption_pubkey_missing_seckey():
    "should fail when trying to encrypt/decrypt with a valid pubkey but no seckey"

