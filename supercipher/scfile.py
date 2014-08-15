import os, tarfile
import strings

class InvalidSuperCipherFile(Exception): pass
class FutureFileVersion(Exception): pass
class InvalidArchive(Exception): pass
class DecryptBeforeLoading(Exception): pass

class SuperCipherFile(object):
    def __init__(self, version):
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

        self.version = version
        self.infile = None

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

    def load(self, supercipher_filename, tmp_dir):
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
        self.ciphertext_filename = os.path.join(tmp_dir, 'archive.tar.gz')
        for i in range(self.crypt_count):
            self.ciphertext_filename += '.gpg'

        # write ciphertext file
        print strings._('scfile_writing_ciphertext')
        outfile = open(self.ciphertext_filename, 'wb')
        buf = None
        while buf != '':
            buf = self.infile.read(1048576)
            outfile.write(buf)

    def decrypt(self, gpg, passphrases, output_dir, ciphers):
        if not self.infile:
            raise DecryptBeforeLoading

        # if there's a pubkey wrapper, decrypt that first 
        if bool(ord(self.ciphers) & self.CIPHERS['pubkey']):
            print strings._('scfile_decrypting_pubkey')
            gpg.pubkey_decrypt(self.ciphertext_filename)
            self.ciphertext_filename_delete_and_truncate()

        # reverse the order of ciphers list
        reversed_ciphers = ciphers[:]
        reversed_ciphers.reverse()

        # decrypt all the layers of symmetric encryption
        for cipher in reversed_ciphers:
            print strings._('scfile_decrypting_symmetric').format(cipher)
            gpg.symmetric_decrypt(self.ciphertext_filename, passphrases[cipher])
            self.ciphertext_filename_delete_and_truncate()

        # extract
        print strings._('scfile_extracting')
        archive_filename = self.ciphertext_filename
        if not tarfile.is_tarfile(archive_filename):
            raise InvalidArchive
        tar = tarfile.open(archive_filename, 'r:gz')
        names = tar.getnames()
        tar.extractall(output_dir)

