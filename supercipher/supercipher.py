import os, sys, inspect, argparse, base64, shutil, hashlib, scrypt, tarfile, subprocess

supercipher_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
version = open('{0}/version'.format(supercipher_dir)).read().strip()

def SuperCipherFile(object):
    def __init__(self):
        self.MAGIC_NUMBER = 0xEBA34B1C

    @staticmethod
    def version_bytes(self):
        strs = version.split('.')
        return chr(int(strs[0])) + chr(int(strs[1])) + chr(int(strs[2]))

def random_string(num_bytes):
    b = os.urandom(num_bytes)
    return base64.b32encode(b).lower().replace('=','')

def get_tmp_dir():
    try:
        while True:
            tmp_dir = os.path.join('/tmp', 'supercipher_{0}'.format(random_string(4)))
            if not os.path.exists(tmp_dir):
                os.makedirs(tmp_dir, 0700)
                return tmp_dir
    except:
        print "Cannot create directory {0}".format(tmp_dir)
        return False

def destroy_tmp_dir(tmp_dir):
    shutil.rmtree(tmp_dir, ignore_errors=True)

def get_passphrase():
    valid_passphrase = False
    while not valid_passphrase:
        # TODO: hide input
        passphrase = raw_input('Enter passphrase: ')
        passphrase2 = raw_input('Retype passphrase: ')
        if passphrase == passphrase2:
            valid_passphrase = True
        else:
            print 'Passwords do not match. Try again:'

    return passphrase

# compress the plaintext file, preserving its filename
def compress(filename, archive_filename):
    print 'Compressing'
    def reset(tarinfo):
        tarinfo.name = os.path.basename(tarinfo.name)
        tarinfo.uid = tarinfo.gid = 0
        tarinfo.uname = tarinfo.gname = "root"
        return tarinfo
    with tarfile.open(archive_filename, 'w:gz') as tar:
        tar.add(filename, recursive=False, filter=reset)

# stretch passphrase into 6 new passphrases
def stretch_passphrase(passphrase, salt, ciphers):
    passphrases = {}
    sys.stdout.write('Deriving passphrases for each cipher:')
    sys.stdout.flush()
    for cipher in ciphers:
        sys.stdout.write(' {0}'.format(cipher))
        sys.stdout.flush()
        passphrase = hashlib.pbkdf2_hmac('sha512', passphrase, salt, 200000)
        passphrase = scrypt.hash(passphrase, salt, N=2**14, r=8, p=1)
        passphrase = base64.b64encode(passphrase)
        passphrases[cipher] = passphrase
    sys.stdout.write('\n')

    return passphrases

# symetrically encrypt using each cipher and passphrase
def symmetrically_encrypt(archive_filename, passphrases, ciphers):
    current_filename = archive_filename
    sys.stdout.write('Encrypting with each cipher:')
    sys.stdout.flush()
    for cipher in ciphers:
        sys.stdout.write(' {0}'.format(cipher))
        sys.stdout.flush()
        p = subprocess.Popen(['/usr/bin/gpg', '--batch', '--no-tty', '--passphrase-fd', '0', '--symmetric', '--cipher-algo', cipher, current_filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.communicate(passphrases[cipher])
        p.wait()
        os.remove(current_filename)
        current_filename += '.gpg'
    sys.stdout.write('\n')
    return current_filename

def encrypt(filename, pubkey):
    print 'Encrypting file {0}'.format(filename)

    salt = os.urandom(16)
    ciphers = ['3des', 'cast5', 'blowfish', 'aes256', 'twofish', 'camellia256']

    tmp_dir = get_tmp_dir()

    archive_filename = os.path.join(tmp_dir, 'archive.tar.gz')
    compress(filename, archive_filename)

    passphrase = get_passphrase()
    passphrases = stretch_passphrase(passphrase, salt, ciphers)
    current_filename = symmetrically_encrypt(archive_filename, passphrases, ciphers)

    # rename file
    supercipher_filename = '{0}.sc'.format(filename)
    os.rename(current_filename, supercipher_filename)
    print 'Superenciphered file: {0}'.format(supercipher_filename)

    # clean up
    destroy_tmp_dir(tmp_dir)

def decrypt(filename):
    print 'Decryption is not implemented yet'

def validate_pubkey(pubkey):
    if len(pubkey) != 40:
        return True, 'Pubkey fingerprint is invalid, must be 40 characters'

    try:
        i = int(pubkey, 16)
    except ValueError:
        return True, 'Pubkey fingerprint is invalid, must be hexadecimal'

    try:
        devnull = open('/dev/null', 'w')
        subprocess.check_call(['/usr/bin/gpg', '--batch', '--no-tty', '--with-colons', '--list-keys', pubkey], stdin=devnull, stdout=devnull, stderr=devnull)
    except subprocess.CalledProcessError:
        return True, 'You do not have a pubkey with that fingerprint'

    return False, False

def main():
    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', nargs=1, help='File to encrypt or decrypt')
    parser.add_argument('--decrypt', action='store_true', dest='decrypt', help='Decrypt a supercipher file')
    parser.add_argument('--pubkey', dest='pubkey', help='Fingerprint of gpg public key to encrypt to')
    args = parser.parse_args()

    filename = os.path.abspath(args.filename[0])
    is_decrypt = bool(args.decrypt)
    pubkey = args.pubkey

    # validation
    if not filename:
        parser.print_help()
        sys.exit(0)
    if not os.path.isfile(filename):
        print '{0} is not a file'.format(filename)
        sys.exit(0)
    if pubkey:
        err, err_message = validate_pubkey(pubkey)
        if err:
            print err_message
            sys.exit(0)

    if is_decrypt:
        decrypt(filename)
    else:
        encrypt(filename, pubkey)

if __name__ == '__main__':
    main()
