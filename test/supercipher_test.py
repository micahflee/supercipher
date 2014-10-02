import os, helper, shutil
from nose import with_setup
from supercipher import *
from supercipher.gnupg import MissingPubkey
supercipher.gpg = GnuPG(homedir=os.path.abspath('test/data/homedir'))

import supercipher.strings
supercipher.strings.load_strings(supercipher.supercipher_dir)

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

    # encrypt
    assert not os.path.exists(output_dir)
    supercipher.encrypt(encrypt_filenames, output_file, None, passphrase)
    assert os.path.isfile(output_file)

    # decrypt
    supercipher.decrypt(output_file, output_dir, passphrase)
    assert os.path.isdir(output_dir)
    assert os.path.isfile('{0}/doc1.odt'.format(output_dir))

@with_setup(setup)
def test_encrypt_decrypt_files_dirs():
    "should be able to encrypt files and directories with a random passphrase and decrypt it again"
    encrypt_filenames = helper.docs_filenames(['doc1.odt', 'doc2.odt', 'spreadsheet.ods', 'more_files'])
    passphrase = helper.random_string(30)

    # encrypt
    assert not os.path.exists(output_dir)
    supercipher.encrypt(encrypt_filenames, output_file, None, passphrase)
    assert os.path.isfile(output_file)

    # decrypt
    supercipher.decrypt(output_file, output_dir, passphrase)
    assert os.path.isdir(output_dir)
    assert os.path.isfile('{0}/doc1.odt'.format(output_dir))
    assert os.path.isfile('{0}/doc2.odt'.format(output_dir))
    assert os.path.isfile('{0}/spreadsheet.ods'.format(output_dir))
    assert os.path.isdir('{0}/more_files'.format(output_dir))
    assert os.path.isfile('{0}/more_files/image.png'.format(output_dir))
    assert os.path.isfile('{0}/more_files/text.txt'.format(output_dir))
    assert os.path.isdir('{0}/more_files/nested'.format(output_dir))
    assert os.path.isfile('{0}/more_files/nested/nested_doc.odt'.format(output_dir))

@with_setup(setup)
def test_encrypt_decrypt_bad_passphrase():
    "should fail when trying to decrypt with a bad passphrase"
    encrypt_filenames = helper.docs_filenames(['doc1.odt', 'doc2.odt', 'spreadsheet.ods'])
    passphrase1 = helper.random_string(30)
    passphrase2 = helper.random_string(30)

    # encrypt
    assert not os.path.exists(output_dir)
    supercipher.encrypt(encrypt_filenames, output_file, None, passphrase1)
    assert os.path.isfile(output_file)

    # decrypt
    supercipher.decrypt(output_file, output_dir, passphrase2)
    assert not os.path.exists(output_dir)

@with_setup(setup)
def test_encrypt_decrypt_pubkey():
    "should be able to encrypt/decrypt files using random passphrase and a pubkey"
    encrypt_filenames = helper.docs_filenames(['doc1.odt', 'doc2.odt', 'spreadsheet.ods'])
    passphrase = helper.random_string(30)
    # we have the public and secret key
    pubkey = '6F6467FDF4462C38FE597CD0CA6C5413CF7BCA9E'

    # encrypt
    assert not os.path.exists(output_dir)
    supercipher.encrypt(encrypt_filenames, output_file, pubkey, passphrase)
    assert os.path.isfile(output_file)

    # decrypt
    supercipher.decrypt(output_file, output_dir, passphrase)
    assert os.path.isdir(output_dir)
    assert os.path.isfile('{0}/doc1.odt'.format(output_dir))
    assert os.path.isfile('{0}/doc2.odt'.format(output_dir))
    assert os.path.isfile('{0}/spreadsheet.ods'.format(output_dir))

@with_setup(setup)
def test_encrypt_decrypt_missing_pubkey():
    "should fail to encrypt when trying to encrypt files using random passphrase and a pubkey that is missing"
    encrypt_filenames = helper.docs_filenames(['doc1.odt', 'doc2.odt', 'spreadsheet.ods'])
    passphrase = helper.random_string(30)
    # we do not have this public key
    pubkey = '0B1491929806596254700155FD720AD9EBA34B1C'

    # encrypt
    assert not os.path.exists(output_dir)
    try:
        supercipher.encrypt(encrypt_filenames, output_file, pubkey, passphrase)
    except MissingPubkey:
        assert True
    else:
        assert False
    assert not os.path.isfile(output_file)

@with_setup(setup)
def test_encrypt_decrypt_missing_seckey():
    "should fail to decrypt when trying to decrypt files encrypted using random passphrase and a seckey that is missing"
    encrypt_filenames = helper.docs_filenames(['doc1.odt', 'doc2.odt', 'spreadsheet.ods'])
    passphrase = helper.random_string(30)
    # we have the public key but not the secret key
    pubkey = '77D4E195BE81A10047B06E4747AA62EF2712261B'

    # encrypt
    assert not os.path.exists(output_dir)
    supercipher.encrypt(encrypt_filenames, output_file, pubkey, passphrase)
    assert os.path.isfile(output_file)

    # decrypt
    supercipher.decrypt(output_file, output_dir, passphrase)
    assert not os.path.exists(output_dir)

