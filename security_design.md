# Security Design

With the exception of the one-time pad, no cipher has been mathematically proven to be secure. Given that intelligence agencies around the world invest massive resources into cryptoanalyic capabilities, as well as government decryption programs like [BULLRUN](https://en.wikipedia.org/wiki/Bullrun_(decryption_program)) and EDGEHILL that seek to place backdoors into civilian crypto, it's likely that some ciphers and key derivation functions that civilians currently believe to be secure actually contain secret weaknesses.

One way to combat this is to encrypt files multiple times using multiple ciphers and separate keys. This is called multiple encryption, or [superencipherment](https://en.wikipedia.org/wiki/Multiple_encryption).

SuperCipher is a user-friendly file encryption tool that makes it simple to encryption files multiple times with multiple keys.

## How it Works

**Encryption**

When using SuperCipher in encryption mode, it accepts the following input:

* A list of files and folders to encrypt
* A passphrase
* Optionally, an OpenPGP public key fingerprint

First, it takes the passphrase and stretches it into three keys using two different key derivation functions, PBKDF2 and scrypt (in case there is a secret weakness in one of them).

* Generates a random salt 16-byte salt
* Generates key1 by:
  * 100000 iterations of PBKDF2 on passphrase (using the salt)
  * 2**14 iterations of scrypt on result from previous function (using the salt)
* Generates key2 by:
  * 100000 iterations of PBKDF2 on key1
  * 2**14 iterations of scrypt on previous result
* Generates key3 by:
  * 100000 iterations of PBKDF2 on key2
  * 2**14 iterations of scrypt on previous result

In the end, key3 is derived from key2, key2 is derived from key1, and key1 is derived from the original passphrase. The keys are derived using both PBKDF2 and scrypt.

Next, it creates a tar archive of all of the files and folders you would like to encrypt, and compresses it with gzip.

Finally, it encrypts the compressed files three times, using these ciphers and passphrases:

* Encrypt with CAST5 using key1 (129-bit key)
* Encrypt with Blowfish using key2 (256-bit key)
* Encrypt with AES256 using key3 (256-bit key)

SuperCipher uses [PyCrypto's implementation](https://www.dlitz.net/software/pycrypto/) of CAST, Blowfish, and AES for its symmetric ciphers.

If the user optionally includes a PGP public key fingerprint, the file is encrypted once more using GnuPG's public key encryption.

The resulting SuperCipher file contains the random salt used to dervice the passphrases, some options (whether a public key is used is the only option so far), and the final superenciphered ciphertext.

**Decryption**

When using SuperCipher in decryption mode, it accepts the following input:

* The SuperCipher file
* A passphrase
* An output folder

Using the salt included in the SuperCipher file and the same method when encrypting, it derives three keys using the passphrase inputed.

If the SuperCipher file states that it was also encrypted to a public key, it tries decrypting with the associated secret key using GnuPG. If the secret key isn't present it fails.

It then tries decrypting the GnuPG file included in the SuperCipher file in reverse order, starting with AES256, then Blowfish, then CAST5.

Finally, it extracts the gzipped tar archive to the output folder.

## Threats it Protects Against

If the attacker has a weakness in some but not all layers of encryption, the file should remain secure. Until the attacker defeats the outer layer (in this case AES256), she cannot attempt to attack the inner layers. If she gets to a cipher that she does not have a weakness for, her attack stops.

If the attacker successfully attacks the outer layer and recovers the key used to encrypt it, she should not be able to use that key to recover the key used to encrypt the next layer. In order to do that she would need to exploit weaknesses in both key deriviation functions.

Because the keys get derived using a random salt, it's not possible to pre-compute a rainbow table of SuperCipher keys.

Dictionary attacks will work against SuperCipher files, but they will be slow and require a large amount of computation resources. To test a single passphrase, the attacker needs to compute 100000 iterations of PBKDF2 and 2**14 iterations of scrypt three times. Since the key derivation is chained, it cannot be computed in parallel. It should be unfeasible for an attacker to guess a good passphrase.
