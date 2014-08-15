import os, helper
from nose import with_setup
from supercipher.gnupg import *

import supercipher.strings
supercipher.strings.load_strings(supercipher.supercipher_dir)

gpg = GnuPG(homedir=os.path.abspath('test/data/homedir'))
plaintext_path = os.path.abspath('test/data/message.txt')
ciphertext_path = os.path.abspath('test/data/message.txt.gpg')

def setup_clean_crypto_files():
    "clean up files from older tests if needed"
    helper.delete_file(plaintext_path)
    helper.delete_file(ciphertext_path)

def test_gnupg_valid_pubkey_valid():
    "GnuPG.valid_pubkey should return true when passing in valid 40-char fingerprint"
    try:
        result1 = gpg.valid_pubkey('6F6467FDF4462C38FE597CD0CA6C5413CF7BCA9E')
        result2 = gpg.valid_pubkey('6f6467fdf4462c38fe597cd0ca6c5413cf7bca9e')
    except:
        assert False
    assert result1 == True
    assert result2 == True

def test_gnupg_valid_pubkey_keyid():
    "GnuPG.valid_pubkey should raise InvalidPubkeyLength exception when passing an 8-char keyid"
    try:
        gpg.valid_pubkey('CF7BCA9E')
    except InvalidPubkeyLength:
        assert True
    else:
        assert False

def test_gnupg_valid_pubkey_not_hex():
    "GnuPG.valid_pubkey should raise InvalidPubkeyNotHex exception when if fingerprint isn't hex"
    try:
        gpg.valid_pubkey('6F6467FDF4462C38FE597CD0CA6C5413CF7BCA9G')
    except InvalidPubkeyNotHex:
        assert True
    else:
        assert False

def test_gnupg_valid_pubkey_missing():
    "GnuPG.valid_pubkey should raise MissingPubkey exception when passing 40-char fingerprint that's not in the gpg keyring"
    try:
        gpg.valid_pubkey('0B1491929806596254700155FD720AD9EBA34B1C')
    except MissingPubkey:
        assert True
    else:
        assert False

@with_setup(setup_clean_crypto_files)
def test_gnupg_symmetric_decrypt_bad_passphrase():
    passphrase = helper.random_string(128)
    plaintext = helper.random_string(256)
    
    # make file with random data
    open(plaintext_path, 'w').write(plaintext)

    # encrypt
    gpg.symmetric_encrypt('aes256', passphrase, plaintext_path)
    helper.delete_file(plaintext_path)

    # decrypt
    try:
        gpg.symmetric_decrypt(ciphertext_path, 'wrong passphrase')
    except InvalidDecryptionPassphrase:
        assert True
    else:
        assert False

@with_setup(setup_clean_crypto_files)
def test_gnupg_symmetric_encryption():
    "should be able to encrypt with GnuPG.symmetric_encrypt and a passphrase, and decrypt with GnuPGP.symmetric_decrypt and same passphrase"
    passphrase = helper.random_string(128)
    plaintext = helper.random_string(256)
    
    # make file with random data
    open(plaintext_path, 'w').write(plaintext)

    # encrypt
    gpg.symmetric_encrypt('aes256', passphrase, plaintext_path)
    helper.delete_file(plaintext_path)

    # decrypt
    gpg.symmetric_decrypt(ciphertext_path, passphrase)
    new_plaintext = open(plaintext_path, 'r').read()

    assert plaintext == new_plaintext

@with_setup(setup_clean_crypto_files)
def test_gnupg_pubkey_encryption():
    "should be able to encrypt with GnuPG.pubkey_encrypt, and decrypt with GnuPGP.pubkey_decrypt with valid pubkey and seckey"
    passphrase = helper.random_string(128)
    plaintext = helper.random_string(256)
    
    # make file with random data
    open(plaintext_path, 'w').write(plaintext)

    # encrypt
    gpg.pubkey_encrypt(plaintext_path, '6F6467FDF4462C38FE597CD0CA6C5413CF7BCA9E')
    helper.delete_file(plaintext_path)

    # decrypt
    gpg.pubkey_decrypt(ciphertext_path)
    new_plaintext = open(plaintext_path, 'r').read()

    assert plaintext == new_plaintext

@with_setup(setup_clean_crypto_files)
def test_gnupg_pubkey_encryption_missing_seckey():
    "when encrypting with GnuPG.pubkey_encrypt, should fail to decrypt with GnuPGP.pubkey_decrypt if seckey is missing"
    passphrase = helper.random_string(128)
    plaintext = helper.random_string(256)
    
    # make file with random data
    open(plaintext_path, 'w').write(plaintext)

    # encrypt
    gpg.pubkey_encrypt(plaintext_path, '77D4E195BE81A10047B06E4747AA62EF2712261B')
    helper.delete_file(plaintext_path)

    # decrypt
    try:
        gpg.pubkey_decrypt(ciphertext_path)
        new_plaintext = open(plaintext_path, 'r').read()
    except MissingSeckey:
        assert True
    else:
        assert False

