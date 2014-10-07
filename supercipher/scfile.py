import os, sys, tarfile, base64, scrypt
from pbkdf2 import PBKDF2

from Crypto.Cipher import AES, Blowfish, CAST, DES
from Crypto import Random
from Crypto.Util import Counter
from struct import pack

import strings, helpers, common

class InvalidSuperCipherFile(Exception): pass
class FutureFileVersion(Exception): pass
class InvalidArchive(Exception): pass
class DecryptBeforeLoading(Exception): pass
class InvalidDecryptionPassphrase(Exception): pass

class SuperCipherFile(object):
    def __init__(self, version=None):
        if not version:
            self.version = common.version
        else:
            self.version = version

        self.MAGIC_NUMBER = '\xEB\xA3\x4B\x1C'
        self.OPTIONS = {
            'pubkey': 0b00000001
        }

        self.infile = None
        self.tmp_dir = helpers.get_tmp_dir()

    def __del__(self):
        if hasattr(self, 'tmp_dir'):
            helpers.destroy_tmp_dir(self.tmp_dir)

    def lock(self, output_filename, filenames, passphrase, pubkey=None):
        timer = helpers.Timer()

        # random salt
        salt = Random.new().read(16)

        # compress files into archive
        timer.start()
        archive_filename = os.path.join(self.tmp_dir, 'archive.tar.gz')
        helpers.compress(filenames, archive_filename)
        print strings._('time_compression').format(timer.stop())

        # derive keys from passphrase
        timer.start()
        keys = self.stretch_passphrase(passphrase, salt)
        print strings._('time_stretching').format(timer.stop())

        # encrypt with symmetric ciphers
        timer.start()
        sys.stdout.write(strings._('encrypt_encrypting_cipher'))
        sys.stdout.flush()

        plaintext = open(archive_filename, 'r').read()
        os.unlink(archive_filename)

        for cipher in common.ciphers:
            sys.stdout.write(' {0}'.format(cipher))
            sys.stdout.flush()

            if cipher == 'aes256':
                # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.AES-module.html
                iv = Random.new().read(AES.block_size)
                cipher = AES.new(keys[cipher], AES.MODE_CFB, iv)
                ciphertext = iv + cipher.encrypt(plaintext)

            elif cipher == 'blowfish':
                # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.Blowfish-module.html
                bs = Blowfish.block_size
                iv = Random.new().read(bs)
                cipher = Blowfish.new(keys[cipher], Blowfish.MODE_CBC, iv)
                plen = bs - divmod(len(plaintext),bs)[1]
                padding = [plen]*plen
                padding = pack('b'*plen, *padding)
                ciphertext = iv + cipher.encrypt(plaintext + padding)

            elif cipher == 'cast5':
                # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.CAST-module.html
                iv = Random.new().read(CAST.block_size)
                cipher = CAST.new(keys[cipher], CAST.MODE_OPENPGP, iv)
                ciphertext = cipher.encrypt(plaintext)

            # today's plaintext is yesterday's ciphertext
            plaintext = ciphertext
        sys.stdout.write('\n')

        # save the new super-enciphered ciphertext
        current_filename = '{0}.cast5.blowfish.aes256'.format(archive_filename)
        open(current_filename, 'w').write(plaintext)

        # encrypt with pubkey
        if pubkey:
            common.gpg.pubkey_encrypt(current_filename, pubkey)
            os.remove(current_filename)
            current_filename += '.gpg'

        # write the output file
        self.save(salt, current_filename, output_filename, bool(pubkey))
        print strings._('time_encryption').format(timer.stop())
        print strings._('encrypt_encrypted_to').format(output_filename)

    def unlock(self, output_dir, input_filename, passphrase):
        # load the supercipher file
        self.load(input_filename)

        # derive keys from passphrase, using input file's salt
        keys = self.stretch_passphrase(passphrase, self.salt)

        # decrypt files
        self.decrypt(keys, output_dir)
        print strings._('decrypt_decrypted_to').format(output_dir)

    # stretch passphrase into 6 new keys
    def stretch_passphrase(self, passphrase, salt):
        keys = {}
        sys.stdout.write(strings._('deriving_keys'))
        sys.stdout.flush()

        # start with the passphrase
        key = passphrase

        # derive a key for each cipher
        for cipher in common.ciphers:
            sys.stdout.write(' {0}'.format(cipher))
            sys.stdout.flush()

            # rounds of pbkdf2 and scrypt
            key = str(PBKDF2.crypt(key, salt.encode('hex'), 100000))
            key = scrypt.hash(key, salt, N=2**14, r=8, p=1)

            if cipher == 'aes256':
                # AES256 needs 256-bit (32-byte) key
                keys[cipher] = key[:32]
            elif cipher == 'blowfish':
                # Blowfish keys very from 32-448 bits, but we'll use 256-bit (32-byte) key
                keys[cipher] = key[:32]
            elif cipher == 'cast5':
                # CAST5 needs 128-bit (16-byte) key
                keys[cipher] = key[:16]

        sys.stdout.write('\n')

        return keys

    def version_to_bytes(self, version):
        strs = version.split('.')
        return chr(int(strs[0])) + chr(int(strs[1])) + chr(int(strs[2]))

    def bytes_to_version(self, bytes):
        return '{0}.{1}.{2}'.format(str(ord(bytes[0])), ord(bytes[1]), ord(bytes[2]))

    def save(self, salt, ciphertext_filename, output_filename, pubkey=False):
        self.salt = salt
        outfile = open(output_filename, 'wb')

        # write magic number (4 bytes)
        outfile.write(self.MAGIC_NUMBER)

        # write version (3 bytes)
        outfile.write(self.version_to_bytes(self.version))

        # write options
        options = 0
        if pubkey:
            options = options | self.OPTIONS['pubkey']
        outfile.write(chr(options))

        # write salt
        outfile.write(salt)

        # write the ciphertext data
        infile = open(ciphertext_filename, 'rb')
        buf = None
        while buf != '':
            buf = infile.read(1048576)
            outfile.write(buf)
        infile.close()

        outfile.close()

    def load(self, supercipher_filename):
        self.infile = open(supercipher_filename, 'rb')

        # file must be at least 24 bytes, plus ciphertext
        if os.stat(supercipher_filename).st_size <= 24:
            raise InvalidSuperCipherFile

        # read header data
        magic_number = self.infile.read(4)
        version = self.infile.read(3)
        options = self.infile.read(1)
        salt = self.infile.read(16)

        # validate headers
        if magic_number != self.MAGIC_NUMBER:
            raise InvalidSuperCipherFile
        version = self.bytes_to_version(version)
        if version > self.version:
            raise FutureFileVersion
        self.options = options
        self.salt = salt

        # build the filename
        self.ciphertext_filename = os.path.join(self.tmp_dir, 'archive.tar.gz.cast5.blowfish.aes256')
        if bool(ord(self.options) & self.OPTIONS['pubkey']):
            self.ciphertext_filename += '.gpg'

        # write ciphertext file
        print strings._('scfile_writing_ciphertext')
        outfile = open(self.ciphertext_filename, 'wb')
        buf = None
        while buf != '':
            buf = self.infile.read(1048576)
            outfile.write(buf)

    def decrypt(self, keys, output_dir):
        if not self.infile:
            raise DecryptBeforeLoading

        # if there's a pubkey wrapper, decrypt that first 
        if bool(ord(self.options) & self.OPTIONS['pubkey']):
            print strings._('scfile_decrypting_pubkey')
            common.gpg.pubkey_decrypt(self.ciphertext_filename)

            # delete the .gpg file
            os.remove(self.ciphertext_filename)
            self.ciphertext_filename = self.ciphertext_filename.rstrip('.gpg')

        # reverse the order of ciphers list
        reversed_ciphers = common.ciphers[:]
        reversed_ciphers.reverse()

        # decrypt all the layers of symmetric encryption
        ciphertext = open(self.ciphertext_filename, 'r').read()
        for cipher in reversed_ciphers:
            try:
                print strings._('scfile_decrypting_symmetric').format(cipher)
                if cipher == 'aes256':
                    bs = AES.block_size
                    eiv = ciphertext[:bs]
                    ciphertext = ciphertext[bs:]
                    cipher = AES.new(keys[cipher], AES.MODE_CFB, eiv)

                if cipher == 'blowfish':
                    bs = Blowfish.block_size
                    eiv = ciphertext[:bs]
                    ciphertext = ciphertext[bs:]
                    cipher = Blowfish.new(keys[cipher], Blowfish.MODE_CBC, eiv)

                if cipher == 'cast5':
                    bs = CAST.block_size
                    eiv = ciphertext[:bs+2]
                    ciphertext = ciphertext[bs+2:]
                    cipher = CAST.new(keys[cipher], CAST.MODE_OPENPGP, eiv)

                plaintext = cipher.decrypt(ciphertext)
            except ValueError:
                raise InvalidDecryptionPassphrase
            ciphertext = plaintext

        # delete the .cast5.blowfish.aes256 file
        os.unlink(self.ciphertext_filename)

        # write archive to disk
        archive_filename = self.ciphertext_filename.rstrip('.cast5.blowfish.aes256')
        open(archive_filename, 'w').write(plaintext)

        # extract
        print strings._('scfile_extracting')
        if not tarfile.is_tarfile(archive_filename):
            raise InvalidArchive
        tar = tarfile.open(archive_filename, 'r:gz')
        names = tar.getnames()
        tar.extractall(output_dir)

