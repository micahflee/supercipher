import shutil, supercipher, helper
from nose import with_setup
from supercipher.scfile import *

output_dir = os.path.abspath('test/data/output_dir')
output_file = os.path.abspath('test/data/output_file')

def setup():
    "make a new tmp_dir"
    global tmp_dir
    tmp_dir = supercipher.get_tmp_dir()
    helper.delete_file(output_file)

def teardown():
    "destroy the existing tmp_dir"
    global tmp_dir
    supercipher.destroy_tmp_dir(tmp_dir)
    shutil.rmtree(output_dir, ignore_errors=True)

def test_scfile_version_to_bytes():
    "SuperCipherFile.version_to_bytes should convert the version to 3 bytes"
    scf = SuperCipherFile(supercipher.version)
    assert scf.version_to_bytes('1.5.9') == '\x01\x05\x09'
    assert scf.version_to_bytes('0.0.3') == '\x00\x00\x03'
    assert scf.version_to_bytes('255.255.255') == '\xff\xff\xff'

def test_scfile_bytes_to_version():
    "SuperCipherFile.bytes_to_version should convert 3 bytes to a version string"
    scf = SuperCipherFile(supercipher.version)
    assert scf.bytes_to_version('\x01\x05\x09') == '1.5.9'
    assert scf.bytes_to_version('\x00\x00\x03') == '0.0.3'
    assert scf.bytes_to_version('\xff\xff\xff') == '255.255.255'

@with_setup(setup, teardown)
def test_scfile_load_small_file():
    "SuperCipher files should all be at least 24 bytes"
    global tmp_dir
    scf = SuperCipherFile(supercipher.version)
    try:
        scf.load(os.path.abspath('test/data/fake_too_small.sc'), tmp_dir)
    except InvalidSuperCipherFile:
        assert True
    else:
        assert False

@with_setup(setup, teardown)
def test_scfile_load_wrong_magic_number():
    "SuperCipher files should begin with the magic number 0xEBA34B1C"
    global tmp_dir
    scf = SuperCipherFile(supercipher.version)
    try:
        scf.load(os.path.abspath('test/data/fake_wrong_magic_number.tc'), tmp_dir)
    except InvalidSuperCipherFile:
        assert True
    else:
        assert False

@with_setup(setup, teardown)
def test_scfile_load_future_version():
    "should throw error if loading a SuperCipher file from a future version"
    global tmp_dir
    scf = SuperCipherFile(supercipher.version)
    try:
        scf.load(os.path.abspath('test/data/fake_future_version.tc'), tmp_dir)
    except FutureFileVersion:
        assert True
    else:
        assert False

@with_setup(setup, teardown)
def test_scfile_decrypt_before_loading():
    "you must run SuperCipherFile.load before .decrypt"
    scf = SuperCipherFile(supercipher.version)
    try:
        scf.decrypt(supercipher.gpg, 'test', output_dir, supercipher.ciphers)
    except DecryptBeforeLoading:
        assert True
    else:
        assert False

@with_setup(setup, teardown)
def test_scfile_decrypt_invalid_archive():
    "should fail when trying to decrypt a SuperCipher file with an invalid .tar.gz inside"
    global tmp_dir
    scf = SuperCipherFile(supercipher.version)
    try:
        scf.load(os.path.abspath('test/data/fake_bad_archive.sc'), tmp_dir)
        passphrases = supercipher.stretch_passphrase('test', scf.salt)
        scf.decrypt(supercipher.gpg, passphrases, output_dir, supercipher.ciphers)
    except InvalidArchive:
        assert True
    else:
        assert False

@with_setup(setup, teardown)
def test_scfile_decrypt():
    "should be able to decrypt a valid SuperCipher file"
    global tmp_dir
    scf = SuperCipherFile(supercipher.version)
    scf.load(os.path.abspath('test/data/real1.sc'), tmp_dir)
    passphrases = supercipher.stretch_passphrase('test', scf.salt)
    scf.decrypt(supercipher.gpg, passphrases, output_dir, supercipher.ciphers)
    plaintext = open('{0}/plaintext.txt'.format(output_dir)).read()
    assert plaintext == 'sample data\n'

@with_setup(setup, teardown)
def test_scfile_save_load():
    "should be able to save a SuperCipher file and reload it successfully"
    global tmp_dir
    salt = supercipher.get_random(16, 16)
    archive_filename = os.path.abspath('test/data/archive.tar.gz')

    # save
    scf = SuperCipherFile(supercipher.version)
    scf.save(salt, archive_filename, output_file, False)
    assert os.path.exists(output_file)

    # load
    scf = SuperCipherFile(supercipher.version)
    scf.load(output_file, tmp_dir)
    assert scf.salt == salt

