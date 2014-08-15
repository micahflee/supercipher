import os, helper
from nose import with_setup
from supercipher import *

output_dir = os.path.abspath('test/data/output_dir')
output_file = os.path.abspath('test/data/output_file')

def setup():
    "make a new tmp_dir"
    shutil.rmtree(output_dir, ignore_errors=True)
    helper.delete_file(output_file)

@with_setup(setup)
def test_encrypt_decrypt():
    "should be able to encrypt a file with a random passphrase and decrypt it again"
    encrypt_filenames = helper.docs_filenames(['doc1.odt'])
    passphrase = helper.random_string(30)

    assert not os.path.exists(output_dir)

    # encrypt
    supercipher.encrypt(encrypt_filenames, output_file, None, passphrase)
    assert os.path.isfile(output_file)

    # decrypt
    supercipher.decrypt(output_file, output_dir, passphrase)
    assert os.path.isdir(output_dir)
    assert os.path.isfile('{0}/doc1.odt'.format(output_dir))


@with_setup(setup)
def test_encrypt_decrypt_multiple_files():
    "should be able to encrypt multiple files with a random passphrase and decrypt it again"
    pass

@with_setup(setup)
def test_encrypt_decrypt_files_dirs():
    "should be able to encrypt files and directories with a random passphrase and decrypt it again"
    pass

@with_setup(setup)
def test_encrypt_decrypt_bad_passphrase():
    "should fail when trying to decrypt with a bad passphrase"

@with_setup(setup)
def test_encrypt_decrypt_pubkey():
    "should be able to encrypt/decrypt files using random passphrase and a pubkey"
    pass

@with_setup(setup)
def test_encrypt_decrypt_missing_pubkey():
    "should fail to encrypt when trying to encrypt files using random passphrase and a pubkey that is missing"
    pass

@with_setup(setup)
def test_encrypt_decrypt_missing_seckey():
    "should fail to decrypt when trying to decrypt files encrypted using random passphrase and a seckey that is missing"
    pass

