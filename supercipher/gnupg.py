import subprocess, os

class InvalidPubkeyLength(Exception): pass
class InvalidPubkeyNotHex(Exception): pass
class MissingPubkey(Exception): pass
class MissingSeckey(Exception): pass
class InvalidDecryptionPassphrase(Exception): pass

class GnuPG(object):

    def __init__(self, homedir=None):
        self.gpg_command = ['/usr/bin/gpg', '--batch', '--no-tty']
        if homedir:
            self.gpg_command.append('--homedir')
            self.gpg_command.append(str(homedir))

        # for suppressing output
        self.devnull = open('/dev/null', 'w')

    def valid_pubkey(self, pubkey):
        if len(pubkey) != 40:
            raise InvalidPubkeyLength

        try:
            i = int(pubkey, 16)
        except ValueError:
            raise InvalidPubkeyNotHex

        try:
            subprocess.check_call(self.gpg_command + ['--with-colons', '--list-keys', pubkey], stdin=self.devnull, stdout=self.devnull, stderr=self.devnull)
        except subprocess.CalledProcessError:
            raise MissingPubkey

        return True

    def symmetric_encrypt(self, cipher, passphrase, filename):
        p = subprocess.Popen(self.gpg_command + ['--passphrase-fd', '0', '--symmetric', '--cipher-algo', cipher, filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.devnull)
        p.communicate(passphrase)
        p.wait()

    def symmetric_decrypt(self, filename, passphrase):
        output_filename = os.path.splitext(filename)[0]
        p = subprocess.Popen(self.gpg_command + ['--output', output_filename, '--passphrase-fd', '0', '--decrypt', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.devnull)
        p.communicate(passphrase)
        returncode = p.wait()
        if returncode != 0:
            raise InvalidDecryptionPassphrase

    def pubkey_encrypt(self, filename, pubkey):
        try:
            subprocess.check_call(self.gpg_command + ['--trust-model', 'always', '--encrypt', '--recipient', pubkey, filename], stdin=self.devnull, stdout=self.devnull, stderr=self.devnull)
        except subprocess.CalledProcessError:
            raise MissingPubkey

    def pubkey_decrypt(self, filename):
        output_filename = os.path.splitext(filename)[0]
        p = subprocess.Popen(self.gpg_command + ['--use-agent', '--output', output_filename, '--decrypt', filename], stdout=subprocess.PIPE, stdin=self.devnull, stderr=self.devnull)
        returncode = p.wait()
        if returncode != 0:
            raise MissingSeckey

