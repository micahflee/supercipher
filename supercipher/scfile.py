import os, sys, tarfile, base64, scrypt
from pbkdf2 import PBKDF2
import strings, helpers, common

class InvalidSuperCipherFile(Exception): pass
class FutureFileVersion(Exception): pass
class InvalidArchive(Exception): pass
class DecryptBeforeLoading(Exception): pass

class SuperCipherFile(object):
    def __init__(self, version=None):
        if not version:
            self.version = common.version
        else:
            self.version = version

        self.MAGIC_NUMBER = '\xEB\xA3\x4B\x1C'
        self.CIPHERS = {
            '3des':        0b10000000,
            'cast5':       0b01000000,
            'blowfish':    0b00100000,
            'aes256':      0b00010000,
            'twofish':     0b00001000,
            'camellia256': 0b00000100,
            'pubkey':      0b00000010,
        }

        self.infile = None
        self.tmp_dir = helpers.get_tmp_dir()

    def __del__(self):
        helpers.destroy_tmp_dir(self.tmp_dir)

    def lock(self, output_filename, filenames, passphrase, pubkey=None):
        # random salt
        salt = helpers.get_random(16, 16)

        # compress files into archive
        archive_filename = os.path.join(self.tmp_dir, 'archive.tar.gz')
        helpers.compress(filenames, archive_filename)

        # derive keys from passphrase
        keys = self.stretch_passphrase(passphrase, salt)

        # encrypt with symmetric ciphers
        current_filename = archive_filename
        sys.stdout.write(strings._('encrypt_encrypting_cipher'))
        sys.stdout.flush()
        for cipher in common.ciphers:
            sys.stdout.write(' {0}'.format(cipher))
            sys.stdout.flush()
            common.gpg.symmetric_encrypt(cipher, keys[cipher], current_filename)
            os.remove(current_filename)
            current_filename += '.gpg'
        sys.stdout.write('\n')

        # encrypt with pubkey
        if pubkey:
            common.gpg.pubkey_encrypt(current_filename, pubkey)
            os.remove(current_filename)
            current_filename += '.gpg'

        # write the output file
        self.save(salt, current_filename, output_filename, bool(pubkey))
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
            elif cipher == '3des':
                # 3DES needs 192-bit (24-byte) key
                keys[cipher] = key[:24]

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

        # write ciphers
        ciphers = self.CIPHERS['3des'] | self.CIPHERS['cast5'] | self.CIPHERS['blowfish'] | \
                  self.CIPHERS['aes256'] | self.CIPHERS['twofish'] | self.CIPHERS['camellia256']
        if pubkey:
            ciphers = ciphers | self.CIPHERS['pubkey']
        outfile.write(chr(ciphers))

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

    def ciphertext_filename_delete_and_truncate(self):
        os.remove(self.ciphertext_filename)
        self.ciphertext_filename = os.path.splitext(self.ciphertext_filename)[0]

    def load(self, supercipher_filename):
        self.infile = open(supercipher_filename, 'rb')

        # file must be at least 24 bytes, plus ciphertext
        if os.stat(supercipher_filename).st_size <= 24:
            raise InvalidSuperCipherFile

        # read header data
        magic_number = self.infile.read(4)
        version = self.infile.read(3)
        ciphers = self.infile.read(1)
        salt = self.infile.read(16)

        # validate headers
        if magic_number != self.MAGIC_NUMBER:
            raise InvalidSuperCipherFile
        version = self.bytes_to_version(version)
        if version > self.version:
            raise FutureFileVersion
        self.ciphers = ciphers
        self.salt = salt

        # how many times was this encrypted?
        self.crypt_count = bin(ord(self.ciphers)).count('1')
        self.ciphertext_filename = os.path.join(self.tmp_dir, 'archive.tar.gz')
        for i in range(self.crypt_count):
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
        if bool(ord(self.ciphers) & self.CIPHERS['pubkey']):
            print strings._('scfile_decrypting_pubkey')
            common.gpg.pubkey_decrypt(self.ciphertext_filename)
            self.ciphertext_filename_delete_and_truncate()

        # reverse the order of ciphers list
        reversed_ciphers = common.ciphers[:]
        reversed_ciphers.reverse()

        # decrypt all the layers of symmetric encryption
        for cipher in reversed_ciphers:
            print strings._('scfile_decrypting_symmetric').format(cipher)
            common.gpg.symmetric_decrypt(self.ciphertext_filename, keys[cipher])
            self.ciphertext_filename_delete_and_truncate()

        # extract
        print strings._('scfile_extracting')
        archive_filename = self.ciphertext_filename
        if not tarfile.is_tarfile(archive_filename):
            raise InvalidArchive
        tar = tarfile.open(archive_filename, 'r:gz')
        names = tar.getnames()
        tar.extractall(output_dir)

