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

    def version_bytes(self):
        strs = self.version.split('.')
        return chr(int(strs[0])) + chr(int(strs[1])) + chr(int(strs[2]))

    def save(self, salt, ciphertext_filename, output_filename, pubkey=False):
        self.salt = salt
        outfile = open(output_filename, 'wb')

        # write magic number (4 bytes)
        outfile.write(self.MAGIC_NUMBER)

        # write version (3 bytes)
        outfile.write(self.version_bytes())

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
