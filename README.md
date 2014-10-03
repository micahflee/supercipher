# SuperCipher

*WARNING: SuperCipher is crypto software, but I'm not a real cryptographer. Don't trust it until it gets reviewed by real cryptographers.*

SuperCipher encrypts a file with a passphrase and optionally a GPG public key.

It stretches the passphrase into several keys (using multiple key derivation functions) and encrypts the file several times using different ciphers and keys each time. In this way, an attacker needs to know of weaknesses in all key derivation functions or all ciphers rather than just one to successfully do a crypto attack against it.

If you supply a public key, it encrypts the file one final time using public key encryption, requiring both the public key and passphrase to decrypt.

The passphrase is stretched into different keys using: PBKDF2, scrypt

Symmetric encryption implementation is [PyCrypto](https://www.dlitz.net/software/pycrypto/), and ciphers used include: CAST5, BLOWFISH, AES

## For Developers

Install dependencies:

```sh
sudo apt-get install build-essential python-all fakeroot python-stdeb python-flask python-qt4 python-scrypt python-pbkdf2 python-crypto
```

Build .deb an install:

```sh
./build_deb.sh
sudo dpkg -i deb_dist/supercipher_*.deb
```

Run tests:

```sh
sudo apt-get install nosetests
nosetests
```

## SuperCipher file format:

```
[4 bytes  ] Magic number 0xEBA34B1C
[3 bytes  ] SuperCipher version major.minor.patch
[1 byte   ] Options: 0x00000001 means pubkey is used
                     (other bits might be used in later versions)
[16 bytes ] Salt for PBKDF2 and scrypt key derivation
[until EOF] Ciphertext
```
