# Security Design

With the exception of the one-time pad, no cipher has been mathematically proven to be secure. Given that intelligence agencies around the world invest massive resources into cryptoanalyic capabilities, as well as government decryption programs like [BULLRUN](https://en.wikipedia.org/wiki/Bullrun_(decryption_program)) and EDGEHILL that seek to place backdoors into civilian crypto, it's likely that some ciphers and key derivation functions that civilians currently believe to be secure actually contain secret weaknesses.

One way to combat this is to encrypt files multiple times using multiple ciphers and separate keys. This is called multiple encryption, or [superencipherment](https://en.wikipedia.org/wiki/Multiple_encryption).

SuperCipher is a user-friendly file encryption tool that makes it simple to encryption files multiple times with multiple keys.

## How it Works

**Encryption**

When using SuperCipher in encryption mode, it accepts the following input:

* A list of files and folders to encrypt
* A passphrase
* Optionally, a PGP public key fingerprint

First, it takes the passphrase and stretches it into six passphrases using two different key derivation functions, PBKDF2 and scrypt (in case there is a secret weakness in one of them).

* Generates a random salt 16-byte salt
* Generates passphrase1 by:
  * 100000 iterations of PBKDF2 on passphrase (using the salt)
  * 2**14 iterations of scrypt on result from previous function (using the salt)
* Generates passphrase2 by:
  * 100000 iterations of PBKDF2 on passphrase1
  * 2**14 iterations of scrypt on previous result
* Continue to generate passphrase3, passphrase4, passphrase5, and passphrase6

In the end, passphrase6 is derived from passphrase5, passphrase5 is derived from passphrase4, and so on. All of the passphrases are originally derived from the original passphrase. The passphrases are derived using both PBKDF2 and scrypt.

Next, it creates a tar archive of all of the files and folders you would like to encrypt, and compresses it further with gzip.

Finally, it encrypts the compressed files six times, using these ciphers and passphrases:

* Encrypt with 3DES using passphrase1
* Encrypt with CAST5 using passphrase2
* Encrypt with BLOWFISH using passphrase3
* Encrypt with AES256 using passphrase4
* Encrypt with TWOFISH using passphrase5
* Encrypt with CAMELLIA256 using passphrase6

All of this encryption is done using GnuPG's options `--symmetric` and `--cipher-algo`.

If the user optionally includes a PGP public key fingerprint, the file is encrypted once more using GnuPG's public key encryption.

The resulting SuperCipher file contains the random salt used to dervice the passphrases, a list of ciphers used, and the final output from encrypting the file several times with GnuPG.

**Decryption**

When using SuperCipher in decryption mode, it accepts the following input:

* The SuperCipher file
* A passphrase
* An output folder

Using the salt included in the SuperCipher file and the same method when encrypting, it derives six passphrases using the passphrase inputed.

If the SuperCipher file states that it was also encrypted to a public key, it tries decrypting with the associated secret key. If the secret key isn't present it fails.

It then tries decrypting the GnuPG file included in the SuperCipher file in reverse order, starting with CAMELLIA256 and passphrase6 and ending with 3DES and passphrase1.

Finally, it extracts the gzipped tar archive to the output folder.

## Threats it Protects Against

If the attacker has a weakness in some but not all layers of encryption, the file should remain secure. Until the attacker defeats the outer layer (in this case CAMELLIA256), he cannot attempt to attack the inner layers. If he gets to a cipher that he does not have a weakness for, his attack stops.

If the attacker successfully attacks the outer layer and recovers the passphrase used to encrypt it, he should not be able to use that passphrase to recover the passphrase used to encrypt the next layer. In order to do that he would need to exploit weaknesses in both key deriviation functions.

Because the passphrases get derived using a random salt, it's not possible to pre-compute a rainbow table of SuperCipher passphrases.

Dictionary attacks will work against SuperCipher files, but they will be slow and require a large amount of computation resources. To test a single passphrase, the attacker needs to compute 100000 iterations of PBKDF2 and 2**14 iterations of scrypt six times. Since the passphrase derivation is chained, it cannot be computed in parallel. With a good passphrase, it should be unfeasible for an attacker to guess.

