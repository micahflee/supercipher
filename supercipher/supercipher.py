import os, sys, inspect, argparse, base64, shutil, hashlib, scrypt, tarfile, getpass
from gnupg import GnuPG, InvalidPubkeyLength, InvalidPubkeyNotHex, MissingPubkey, MissingSeckey, InvalidDecryptionPassphrase
from scfile import SuperCipherFile, InvalidSuperCipherFile, FutureFileVersion, InvalidArchive
from pbkdf2 import PBKDF2

supercipher_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
version = open('{0}/version'.format(supercipher_dir)).read().strip()

ciphers = ['3des', 'cast5', 'blowfish', 'aes256', 'twofish', 'camellia256']

gpg = GnuPG()

def get_random(bits_of_entropy, bytes_returned=64):
    return hashlib.sha512(os.urandom(bits_of_entropy)).digest()[:bytes_returned]

def get_tmp_dir():
    try:
        while True:
            random_string = base64.b32encode(get_random(4, 16)).lower().replace('=','')
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
            passphrase = getpass.getpass('Enter passphrase: ')
            passphrase2 = getpass.getpass('Retype passphrase: ')
            if passphrase == passphrase2:
                valid_passphrase = True
            else:
                print 'Passwords do not match. Try again:'
    else:
        passphrase = getpass.getpass('Enter passphrase: ')

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
        passphrase = str(PBKDF2.crypt(passphrase, salt.encode('hex'), 100000))
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

    salt = get_random(16, 16)
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
    parser.add_argument('--encrypt', '-e', metavar='filename', nargs='+', help='Files and folders to encrypt')
    parser.add_argument('--decrypt', '-d', metavar='filename', dest='decrypt', help='Filename of supercipher file to decrypt')
    parser.add_argument('--pubkey', '-p', metavar='public_key', dest='pubkey', help='Fingerprint of gpg public key to encrypt to')
    args = parser.parse_args()

    encrypt_filenames = args.encrypt
    decrypt_filename = args.decrypt
    pubkey = args.pubkey

    # convert filenames to absolute paths
    if encrypt_filenames:
        for i in range(len(encrypt_filenames)):
            encrypt_filenames[i] = os.path.abspath(encrypt_filenames[i])
    if decrypt_filename:
        decrypt_filename = os.path.abspath(decrypt_filename)

    # validation
    if not encrypt_filenames and not decrypt_filename:
        parser.print_help()
        print ''
        print 'You must either encrypt or decrypt a file'
        sys.exit(0)
    if encrypt_filenames and decrypt_filename:
        print 'You cannot encrypt and decrypt files in the same command'
        sys.exit(0)

    if encrypt_filenames:
        action = 'encrypt'
    else:
        action = 'decrypt'

    # encrypt validation
    if action == 'encrypt':
        # make sure encrypt_filenames is a list of valid files/folders
        valid = True
        for filename in encrypt_filenames:
            if not os.path.exists(filename):
                print '{0} is not a file or folder'.format(filename)
                valid = False
        if not valid:
            print 'Some of the filenames you want to encrypt are invalid'
            sys.exit(0)

        # if pubkey is passed, make sure the fingerprint is valid
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

    elif action == 'decrypt':
        # make sure decrypt_filename is a valid file
        if not os.path.isfile(decrypt_filename):
            print '{0} is not a file'.format(decrypt_filename)
            sys.exit(0)

    # execute the action
    if action == 'encrypt':
        encrypt(encrypt_filenames, pubkey)
    else:
        decrypt(filename)

if __name__ == '__main__':
    main()
