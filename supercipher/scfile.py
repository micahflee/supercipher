class SuperCipherFile(object):
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

    def save(self, version, salt, ciphertext_filename, output_filename, pubkey=False):
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

        # write the ciphertext data
        infile = open(ciphertext_filename, 'rb')
        buf = None
        while buf != '':
            buf = infile.read(1048576)
            outfile.write(buf)
        infile.close()

        outfile.close()

    def load(self, supercipher_filename, tmp_dir):
        pass

