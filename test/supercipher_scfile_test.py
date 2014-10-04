import shutil, supercipher, helper
from nose import with_setup
from supercipher.scfile import *

import supercipher.strings as strings
import supercipher.common as common
strings.load_strings(common.supercipher_dir)

output_dir = os.path.abspath('test/data/output_dir')
output_file = os.path.abspath('test/data/output_file')

def test_scfile_version_to_bytes():
    "SuperCipherFile.version_to_bytes should convert the version to 3 bytes"
    scf = SuperCipherFile()
    assert scf.version_to_bytes('1.5.9') == '\x01\x05\x09'
    assert scf.version_to_bytes('0.0.3') == '\x00\x00\x03'
    assert scf.version_to_bytes('255.255.255') == '\xff\xff\xff'

def test_scfile_bytes_to_version():
    "SuperCipherFile.bytes_to_version should convert 3 bytes to a version string"
    scf = SuperCipherFile()
    assert scf.bytes_to_version('\x01\x05\x09') == '1.5.9'
    assert scf.bytes_to_version('\x00\x00\x03') == '0.0.3'
    assert scf.bytes_to_version('\xff\xff\xff') == '255.255.255'

def test_scfile_load_small_file():
    "SuperCipher files should all be at least 24 bytes"
    scf = SuperCipherFile()
    try:
        scf.load(os.path.abspath('test/data/fake_too_small.sc'))
    except InvalidSuperCipherFile:
        assert True
    else:
        assert False

def test_scfile_load_wrong_magic_number():
    "SuperCipher files should begin with the magic number 0xEBA34B1C"
    scf = SuperCipherFile()
    try:
        scf.load(os.path.abspath('test/data/fake_wrong_magic_number.tc'))
    except InvalidSuperCipherFile:
        assert True
    else:
        assert False

def test_scfile_load_future_version():
    "should throw error if loading a SuperCipher file from a future version"
    scf = SuperCipherFile()
    try:
        scf.load(os.path.abspath('test/data/fake_future_version.tc'))
    except FutureFileVersion:
        assert True
    else:
        assert False

def test_scfile_decrypt_before_loading():
    "you must run SuperCipherFile.load before .decrypt"
    scf = SuperCipherFile()
    try:
        scf.decrypt('test', output_dir)
    except DecryptBeforeLoading:
        assert True
    else:
        assert False

def test_scfile_decrypt_invalid_passphrase():
    "should fail when trying to decrypt a SuperCipher file using an invalid passphrase"
    scf = SuperCipherFile()
    try:
        scf.load(os.path.abspath('test/data/real1.sc'))
        keys = scf.stretch_passphrase('WRONG', scf.salt)
        scf.decrypt(keys, output_dir)
    except InvalidDecryptionPassphrase:
        assert True
    else:
        assert False

def test_scfile_decrypt_invalid_archive():
    "should fail when trying to decrypt a SuperCipher file with an invalid .tar.gz inside"
    scf = SuperCipherFile()
    try:
        scf.load(os.path.abspath('test/data/fake_bad_archive.sc'))
        keys = scf.stretch_passphrase('test', scf.salt)
        scf.decrypt(keys, output_dir)
    except InvalidArchive:
        assert True
    else:
        assert False

def test_scfile_decrypt():
    "should be able to decrypt a valid SuperCipher file"
    scf = SuperCipherFile()
    scf.load(os.path.abspath('test/data/real1.sc'))
    keys = scf.stretch_passphrase('test', scf.salt)
    scf.decrypt(keys, output_dir)
    plaintext = open('{0}/plaintext.txt'.format(output_dir)).read()
    assert plaintext == 'sample data\n'

def test_scfile_save_load():
    "should be able to save a SuperCipher file and reload it successfully"
    salt = supercipher.helpers.get_random(16, 16)
    archive_filename = os.path.abspath('test/data/archive.tar.gz')

    # save
    scf = SuperCipherFile()
    scf.save(salt, archive_filename, output_file, False)
    assert os.path.exists(output_file)

    # load
    scf = SuperCipherFile()
    scf.load(output_file)
    assert scf.salt == salt

