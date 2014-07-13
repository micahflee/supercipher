# Supercipher

*WARNING: Supercipher is crypto software, but I'm not a real cryptographer. Don't trust it until it gets reviewed by real cryptographers.*

Supercipher encrypts a file with a passphrase and optionally a GPG public key.

It stretches the passphrase into several keys (using multiple key derivation functions) and encrypts the file several times using different ciphers and keys each time. In this way, an attacker needs to know of weaknesses in all key derivation functions or all ciphers rather than just one to successfully do a crypto attack against it.

If you supply a public key, it encrypts the file one final time using public key encryption, requiring both the public key and passphrase to decrypt.

The passphrase is stretched into different keys using: PBKDF2, scrypt
Symmetric encryption is outsourced to GPG, and ciphers used include: 3DES, CAST5, BLOWFISH, AES256, TWOFISH, CAMELLIA256

## For Developers

Install dependencies:

'''sh
sudo apt-get install build-essential python-all fakeroot python-stdeb python-flask python-qt4 python-script
'''

Supercipher file format:

    [4 bytes  ] Magic number 0xEBA34B1C
    [3 bytes  ] Supercipher version major.minor.patch
    [1 byte   ] Ciphers used: 1 is use, 0 is don't use, in this order:
                3DES, CAST5, BLOWFISH, AES256, TWOFISH, CAMELLIA256, pubkey
                (the last bit is always 0)
    [16 bytes ] Salt for PBKDF2 key derivation
    [until EOF] Ciphertext

