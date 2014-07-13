import subprocess

class InvalidPubkeyLength: pass
class InvalidPubkeyNotHex: pass
class MissingPubkey: pass

class GnuPG(object):

    def __init__(self):
        self.gpg_bin = '/usr/bin/gpg'

    def valid_pubkey(self, pubkey):
        if len(pubkey) != 40:
            raise InvalidPubkeyLength

        try:
            i = int(pubkey, 16)
        except ValueError:
            raise InvalidPubkeyNotHex

        try:
            devnull = open('/dev/null', 'w')
            subprocess.check_call([self.gpg_bin, '--batch', '--no-tty', '--with-colons', '--list-keys', pubkey], stdin=devnull, stdout=devnull, stderr=devnull)
        except subprocess.CalledProcessError:
            raise MissingPubkey

        return True 

    def symmetrically_encrypt(self, cipher, passphrase, filename):
        p = subprocess.Popen([self.gpg_bin, '--batch', '--no-tty', '--passphrase-fd', '0', '--symmetric', '--cipher-algo', cipher, filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.communicate(passphrase)
        p.wait()

    def pubkey_encrypt(self, filename, pubkey):
        subprocess.Popen([self.gpg_bin, '--batch', '--no-tty', '--trust-model', 'always', '--encrypt', '--hidden-recipient', pubkey, filename])


