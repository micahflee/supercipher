import os, sys, inspect, argparse, base64, shutil, hashlib, scrypt, tarfile
from gnupg import GnuPG, InvalidPubkeyLength, InvalidPubkeyNotHex, MissingPubkey, MissingSeckey, InvalidDecryptionPassphrase 
from scfile import SuperCipherFile, InvalidSuperCipherFile, FutureFileVersion, InvalidArchive

supercipher_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
version = open('{0}/version'.format(supercipher_dir)).read().strip()

ciphers = ['3des', 'cast5', 'blowfish', 'aes256', 'twofish', 'camellia256']

gpg = GnuPG()

def get_tmp_dir():
    try:
        while True:
            random_string = base64.b32encode(os.urandom(4)).lower().replace('=','')
            tmp_dir = os.path.join('/tmp', 'supercipher_{0}'.format(random_string))
            if not os.path.exists(tmp_dir):
                os.makedirs(tmp_dir, 0700)
                return tmp_dir
    except:
        print "Cannot create directory {0}".format(tmp_dir)
        return False

def destroy_tmp_dir(tmp_dir):
    shutil.rmtree(tmp_dir, ignore_errors=True)

def get_passphrase(ask_twice=False):
    if ask_twice:
        valid_passphrase = False
        while not valid_passphrase:
            passphrase = raw_input('Enter passphrase: ')
            passphrase2 = raw_input('Retype passphrase: ')
            if passphrase == passphrase2:
                valid_passphrase = True
            else:
                print 'Passwords do not match. Try again:'
    else:
        passphrase = raw_input('Enter passphrase: ')

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
def stretch_passphrase(passphrase, salt):
    global ciphers
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
def symmetric_encrypt(archive_filename, passphrases):
    global gpg, ciphers
    current_filename = archive_filename
    sys.stdout.write('Encrypting with each cipher:')
    sys.stdout.flush()
    for cipher in ciphers:
        sys.stdout.write(' {0}'.format(cipher))
        sys.stdout.flush()
        gpg.symmetric_encrypt(cipher, passphrases[cipher], current_filename)
        os.remove(current_filename)
        current_filename += '.gpg'
    sys.stdout.write('\n')
    return current_filename

# encrypt to the public key, if it was given
def pubkey_encrypt(filename, pubkey):
    if pubkey:
        global gpg
        gpg.pubkey_encrypt(filename, pubkey)
        os.remove(filename)
        filename += '.gpg'

    return filename


def encrypt(filename, pubkey):
    print 'Encrypting file {0}'.format(filename)

    salt = os.urandom(16)
    tmp_dir = get_tmp_dir()

    try:
        archive_filename = os.path.join(tmp_dir, 'archive.tar.gz')
        compress(filename, archive_filename)

        passphrase = get_passphrase(True)
        passphrases = stretch_passphrase(passphrase, salt)
        current_filename = symmetric_encrypt(archive_filename, passphrases)
        current_filename = pubkey_encrypt(current_filename, pubkey)

        # write the supercipher file
        supercipher_filename = '{0}.sc'.format(filename)
        scf = SuperCipherFile(version)
        scf.save(salt, current_filename, supercipher_filename, bool(pubkey))
        print 'Superenciphered file: {0}'.format(supercipher_filename)
    except KeyboardInterrupt:
        print 'Canceling and cleaning up'

    # clean up
    destroy_tmp_dir(tmp_dir)

def decrypt(filename):
    print 'Decrypting file {0}'.format(filename)

    tmp_dir = get_tmp_dir()
    plaintext_dir = os.path.dirname(filename)

    try:
        scf = SuperCipherFile(version)
        scf.load(filename, tmp_dir)
        passphrase = get_passphrase()
        passphrases = stretch_passphrase(passphrase, scf.salt)
        plaintext_filename = scf.decrypt(gpg, passphrases, plaintext_dir, ciphers)
        print 'Decrypted file is: {0}'.format(plaintext_filename)

    except InvalidSuperCipherFile:
        print '{0} does not appear to be a valid SuperCipher file'.format(filename)
    except FutureFileVersion:
        print 'This file appears to have been created with a newer version of SuperCipher. Please upgrade and try again.'
    except InvalidArchive:
        print 'Something went wrong during the decryption.'
    except MissingSeckey:
        print 'Cannot decrypt SuperCipher file, you do not have the right secret key.'
    except InvalidDecryptionPassphrase:
        print 'Invalid passphrase.'
    except KeyboardInterrupt:
        print 'Canceling and cleaning up'

    # clean up
    destroy_tmp_dir(tmp_dir)

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
        global gpg
        try:
            gpg.valid_pubkey(pubkey)
        except InvalidPubkeyLength:
            print 'Pubkey fingerprint is invalid, must be 40 characters'
            sys.exit(0)
        except InvalidPubkeyNotHex:
            print 'Pubkey fingerprint is invalid, must be hexadecimal'
            sys.exit(0)
        except MissingPubkey:
            print 'You do not have a pubkey with that fingerprint'
            sys.exit(0)

    if is_decrypt:
        decrypt(filename)
    else:
        encrypt(filename, pubkey)

if __name__ == '__main__':
    main()
