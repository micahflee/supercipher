def SuperCipherFile(object):
    def __init__(self):
        self.MAGIC_NUMBER = 0xEBA34B1C

    @staticmethod
    def version_bytes(self):
        strs = version.split('.')
        return chr(int(strs[0])) + chr(int(strs[1])) + chr(int(strs[2]))


