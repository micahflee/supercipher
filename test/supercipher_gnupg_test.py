import os
from supercipher.gnupg import *

gpg = GnuPG(homedir=os.path.abspath('test/data/homedir'))

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

def test_gnupg_symmetric_encryption():
    "should be able to encrypt with GnuPG.symmetric_encrypt and a passphrase, and decrypt withe GnuPGP.symmetric_decrypt and same passphrase"
    pass

def test_gnupg_pubkey_encryption():
    "should be able to encrypt with GnuPG.pubkey_encrypt, and decrypt withe GnuPGP.pubkey_decrypt"
    pass
