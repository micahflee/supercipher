import os, sys, inspect, argparse, base64, shutil, hashlib, scrypt, tarfile, subprocess

supercipher_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
version = open('{0}/version'.format(supercipher_dir)).read().strip()

def SupercipherFile(object):
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

def encrypt(filename, pubkey):
    print 'Encrypting file {0}'.format(filename)
    tmp_dir = get_tmp_dir()

    # get passphrase
    valid_passphrase = False
    while not valid_passphrase:
        # TODO: hide input
        passphrase = raw_input('Enter passphrase: ')
        passphrase2 = raw_input('Retype passphrase: ')
        if passphrase == passphrase2:
            valid_passphrase = True
        else:
            print 'Passwords do not match. Try again:'

    # compress the plaintext file, preserving its filename
    print 'Compressing'
    archive_filename = os.path.join(tmp_dir, 'archive.tar.gz')
    def reset(tarinfo):
        tarinfo.name = os.path.basename(tarinfo.name)
        tarinfo.uid = tarinfo.gid = 0
        tarinfo.uname = tarinfo.gname = "root"
        return tarinfo
    with tarfile.open(archive_filename, 'w:gz') as tar:
        tar.add(filename, recursive=False, filter=reset)

    # stretch passphrase into 6 keys
    salt = os.urandom(16)
    rounds = 200000
    ciphers = ['3des', 'cast5', 'blowfish', 'aes256', 'twofish', 'camellia256']
    passphrases = {}
    sys.stdout.write('Deriving passphrases for each cipher:')
    sys.stdout.flush()
    for cipher in ciphers:
        sys.stdout.write(' {0}'.format(cipher))
        sys.stdout.flush()
        passphrase = hashlib.pbkdf2_hmac('sha512', passphrase, salt, rounds)
        passphrase = scrypt.hash(passphrase, salt, N=2**14, r=8, p=1)
        passphrase = base64.b64encode(passphrase)
        passphrases[cipher] = passphrase
    sys.stdout.write('\n')
    print passphrases

    # symetrically encrypt using each cipher and passphrase
    print 'TODO: figure out how to use gpg --symmetric with --batch'
    current_filename = archive_filename
    sys.stdout.write('Encrypting with each cipher:')
    sys.stdout.flush()
    for cipher in ciphers:
        sys.stdout.write(' {0}'.format(cipher))
        sys.stdout.flush()
        p = subprocess.Popen(['/usr/bin/gpg', '--batch', '--no-tty', '--symmetric', '--cipher-algo', cipher, current_filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.communicate(passphrases[cipher])
        p.wait()
        os.remove(current_filename)
        current_filename += '.gpg'
    sys.stdout.write('\n')

    # clean up
    destroy_tmp_dir(tmp_dir)

def decrypt(filename):
    print 'Decryption is not implemented yet'

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

    if is_decrypt:
        decrypt(filename)
    else:
        encrypt(filename, pubkey)

if __name__ == '__main__':
    main()
