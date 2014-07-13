import subprocess, os

class InvalidPubkeyLength(Exception): pass
class InvalidPubkeyNotHex(Exception): pass
class MissingPubkey(Exception): pass
class MissingSeckey(Exception): pass
class InvalidDecryptionPassphrase(Exception): pass

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

    def symmetric_encrypt(self, cipher, passphrase, filename):
        p = subprocess.Popen([self.gpg_bin, '--batch', '--no-tty', '--passphrase-fd', '0', '--symmetric', '--cipher-algo', cipher, filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.communicate(passphrase)
        p.wait()

    def symmetric_decrypt(self, filename, passphrase):
        output_filename = os.path.splitext(filename)[0]
        p = subprocess.Popen([self.gpg_bin, '--batch', '--no-tty', '--output', output_filename, '--passphrase-fd', '0', '--decrypt', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.communicate(passphrase)
        returncode = p.wait()
        if returncode != 0:
            raise InvalidDecryptionPassphrase

    def pubkey_encrypt(self, filename, pubkey):
        subprocess.check_call([self.gpg_bin, '--batch', '--no-tty', '--trust-model', 'always', '--encrypt', '--recipient', pubkey, filename])

    def pubkey_decrypt(self, filename):
        output_filename = os.path.splitext(filename)[0]
        p = subprocess.Popen([self.gpg_bin, '--batch', '--no-tty', '--use-agent', '--output', output_filename, '--decrypt', filename], stdout=subprocess.PIPE)
        returncode = p.wait()
        if returncode != 0:
            raise MissingSeckey

