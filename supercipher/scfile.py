import os, tarfile

class InvalidSuperCipherFile(Exception): pass
class FutureFileVersion(Exception): pass
class InvalidArchive(Exception): pass

class SuperCipherFile(object, version):
    def __init__(self): 
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

    def version_to_bytes(self, version):
        strs = version.split('.')
        return chr(int(strs[0])) + chr(int(strs[1])) + chr(int(strs[2]))

    def bytes_to_version(self, bytes):
        return '{0}.{1}.{2}'.format(str(int(bytes[0])), int(bytes[1])), int(bytes[2])))

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

    def delete_and_truncate(self, filename):
        os.remove(filename)
        filename = os.path.splitext(filename)[0]
        return filename

    def load_and_decrypt(self, gpg, supercipher_filename, plaintext_dir, tmp_dir):
        infile = open(supercipher_filename, 'rb')

        # file must be at least 24 bytes, plus ciphertext
        if os.stat(supercipher_filename).st_size <= 24:
            raise InvalidSuperCipherFile

        # read header data
        magic_number = infile.read(4)
        version = infile.read(3)
        ciphers = infile.read(1)
        salt = infile.read(16)

        # validate headers
        if magic_number != self.MAGIC_NUMBER:
            raise InvalidSuperCipherFile
        version = self.bytes_to_version(version)
        if version > self.version:
            raise FutureFileVersion
        self.ciphers = ciphers
        self.salt = salt

        # how many times was this encrypted?
        crypt_count = bin(self.ciphers).count('1')
        ciphertext_filename = os.path.join(tmp_dir, 'archive.tar.gz')
        for i in range(crypt_count):
            ciphertext_filename += '.gpg'

        # if there's a pubkey wrapper, decrypt that first 
        if bool(self.ciphers & self.CIPHERS['pubkey']):
            gpg.pubkey_decrypt(ciphertext_filename)
            ciphertext_filename = self.delete_and_truncate(ciphertext_filename)

        # decrypt all the layers of symmetric encryption
        for i in range(crypt_count-1):
            gpg.symmetric_decrypt(ciphertext_filename)
            ciphertext_filename = self.delete_and_truncate(ciphertext_filename)

        # extract
        archive_filename = ciphertext_filename
        if not tarfile.is_tarfile(archive_filename):
            raise InvalidArchive
        tar = tarfile.TarFile(archive_filename)
        tar.extractall(plaintext_dir)

