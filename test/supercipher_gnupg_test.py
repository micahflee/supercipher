import os
from supercipher.gnupg import *

def test_gnupg_valid_pubkey_valid():
    "GnuPG.valid_pubkey should return true when passing in valid 40-char fingerprint"
    gpg = GnuPG(homedir=os.path.abspath('test/data/homedir'))
    try:
        result1 = gpg.valid_pubkey('6F6467FDF4462C38FE597CD0CA6C5413CF7BCA9E')
        result2 = gpg.valid_pubkey('6f6467fdf4462c38fe597cd0ca6c5413cf7bca9e')
    except:
        assert False
    assert result1 == True
    assert result2 == True

def test_gnupg_valid_pubkey_keyid():
    "GnuPG.valid_pubkey should raise InvalidPubkeyLength exception when passing an 8-char keyid"
    pass

def test_gnupg_valid_pubkey_not_hex():
    "GnuPG.valid_pubkey should raise InvalidPubkeyNotHex exception when if fingerprint isn't hex"
    pass

def test_gnupg_valid_pubkey_missing():
    "GnuPG.valid_pubkey should raise MissingPubkey exception when passing 40-char fingerprint that's not in the gpg keyring"
    pass

def test_gnupg_symmetric_encryption():
    "should be able to encrypt with GnuPG.symmetric_encrypt and a passphrase, and decrypt withe GnuPGP.symmetric_decrypt and same passphrase"
    pass

def test_gnupg_pubkey_encryption():
    "should be able to encrypt with GnuPG.pubkey_encrypt, and decrypt withe GnuPGP.pubkey_decrypt"
    pass
