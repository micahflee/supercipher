import os, inspect
import gnupg

supercipher_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
version = open('{0}/version'.format(supercipher_dir)).read().strip()

ciphers = ['3des', 'cast5', 'blowfish', 'aes256']

gpg = gnupg.GnuPG()
