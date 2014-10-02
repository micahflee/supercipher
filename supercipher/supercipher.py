import os, sys, inspect, argparse, base64, scrypt
from gnupg import GnuPG, InvalidPubkeyLength, InvalidPubkeyNotHex, MissingPubkey, MissingSeckey, InvalidDecryptionPassphrase
from scfile import SuperCipherFile, InvalidSuperCipherFile, FutureFileVersion, InvalidArchive
from pbkdf2 import PBKDF2

import strings, helpers

supercipher_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
version = open('{0}/version'.format(supercipher_dir)).read().strip()

ciphers = ['3des', 'cast5', 'blowfish', 'aes256', 'twofish', 'camellia256']

gpg = GnuPG()

# stretch passphrase into 6 new keys
def stretch_passphrase(passphrase, salt):
    global ciphers
    keys = {}
    sys.stdout.write(strings._('deriving_keys'))
    sys.stdout.flush()

    # start with the passphrase
    key = passphrase

    # derive a key for each cipher
    for cipher in ciphers:
        sys.stdout.write(' {0}'.format(cipher))
        sys.stdout.flush()

        # rounds of pbkdf2 and scrypt
        key = str(PBKDF2.crypt(key, salt.encode('hex'), 100000))
        key = scrypt.hash(key, salt, N=2**14, r=8, p=1)
        key = base64.b64encode(key)
        keys[cipher] = key
    sys.stdout.write('\n')

    return keys

# symetrically encrypt using each cipher and passphrase
def symmetric_encrypt(archive_filename, keys):
    global gpg, ciphers
    current_filename = archive_filename
    sys.stdout.write(strings._('encrypt_encrypting_cipher'))
    sys.stdout.flush()
    for cipher in ciphers:
        sys.stdout.write(' {0}'.format(cipher))
        sys.stdout.flush()
        gpg.symmetric_encrypt(cipher, keys[cipher], current_filename)
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

def encrypt(filenames, output_filename, pubkey=None, passphrase=None):
    print strings._('encrypt_encrypting_files').format(filenames)

    salt = helpers.get_random(16, 16)
    tmp_dir = helpers.get_tmp_dir()

    try:
        archive_filename = os.path.join(tmp_dir, 'archive.tar.gz')
        helpers.compress(filenames, archive_filename)

        if not passphrase:
            passphrase = helpers.get_passphrase(True)
        keys = stretch_passphrase(passphrase, salt)
        current_filename = symmetric_encrypt(archive_filename, keys)
        current_filename = pubkey_encrypt(current_filename, pubkey)

        # write the output file
        scf = SuperCipherFile(version)
        scf.save(salt, current_filename, output_filename, bool(pubkey))
        print strings._('encrypt_encrypted_to').format(output_filename)
    except KeyboardInterrupt:
        print strings._('cleanup')

    # clean up
    helpers.destroy_tmp_dir(tmp_dir)

def decrypt(filename, output_dir, passphrase=None):
    print strings._('decrypt_decrypting_file').format(filename)

    tmp_dir = helpers.get_tmp_dir()

    try:
        scf = SuperCipherFile(version)
        scf.load(filename, tmp_dir)
        if not passphrase:
            passphrase = helpers.get_passphrase()
        keys = stretch_passphrase(passphrase, scf.salt)
        scf.decrypt(gpg, keys, output_dir, ciphers)
        print strings._('decrypt_decrypted_to').format(output_dir)

    except InvalidSuperCipherFile:
        print strings._('decrypt_error_invalid_file').format(filename)
    except FutureFileVersion:
        print strings._('decrypt_error_future_version')
    except InvalidArchive:
        print strings._('decrypt_error_invalid_archive')
    except MissingSeckey:
        print strings._('decrypt_error_missing_seckey')
    except InvalidDecryptionPassphrase:
        print strings._('decrypt_error_invalid_passphrase')
    except KeyboardInterrupt:
        print strings._('cleanup')

    # clean up
    helpers.destroy_tmp_dir(tmp_dir)

def main():
    strings.load_strings(supercipher_dir)

    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-e', '--encrypt', metavar='filename', nargs='+', help=strings._('arg_help_encrypt'))
    parser.add_argument('-d', '--decrypt', metavar='filename', dest='decrypt', help=strings._('arg_help_decrypt'))
    parser.add_argument('-p', '--pubkey', metavar='public_key', dest='pubkey', help=strings._('arg_help_pubkey'))
    parser.add_argument('-o', '--output', metavar='filename', dest='output', required=True, help=strings._('arg_help_output'))
    args = parser.parse_args()

    encrypt_filenames = args.encrypt
    decrypt_filename = args.decrypt
    pubkey = args.pubkey
    output_filename = args.output

    # convert filenames to absolute paths
    if encrypt_filenames:
        for i in range(len(encrypt_filenames)):
            encrypt_filenames[i] = os.path.abspath(encrypt_filenames[i])
    if decrypt_filename:
        decrypt_filename = os.path.abspath(decrypt_filename)
    output_filename = os.path.abspath(output_filename)

    # validation
    if not encrypt_filenames and not decrypt_filename:
        parser.print_help()
        print ''
        print strings._('validation_choose_one')
        sys.exit(0)
    if encrypt_filenames and decrypt_filename:
        print strings._('validation_dont_choose_two')
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
                print strings._('validation_doesnt_exist').format(filename)
                valid = False
        if not valid:
            print strings._('validation_invalid_file')
            sys.exit(0)

        # if pubkey is passed, make sure the fingerprint is valid
        if pubkey:
            global gpg
            try:
                gpg.valid_pubkey(pubkey)
            except InvalidPubkeyLength:
                print strings._('validation_pubkey_length')
                sys.exit(0)
            except InvalidPubkeyNotHex:
                print strings._('validation_pubkey_not_hex')
                sys.exit(0)
            except MissingPubkey:
                print strings._('validation_missing_pubkey')
                sys.exit(0)

        # make sure output_filename doesn't already exist
        if os.path.exists(output_filename):
            print strings._('validation_output_exists').format(output_filename)
            sys.exit(0)

    elif action == 'decrypt':
        # make sure decrypt_filename is a valid file
        if not os.path.isfile(decrypt_filename):
            print strings._('validation_not_file').format(decrypt_filename)
            sys.exit(0)

        # make sure output_filename either doesn't exist or is a writable folder
        if os.path.exists(output_filename):
            if os.path.isdir(output_filename):
                if not os.access(output_filename, os.W_OK):
                    print strings._('validation_not_writable').format(output_filename)
                    sys.exit(0)
            else:
                print strings._('validation_already_exists').format(output_filename)
                sys.exit(0)

    # execute the action
    if action == 'encrypt':
        encrypt(encrypt_filenames, output_filename, pubkey)
    else:
        decrypt(decrypt_filename, output_filename)

if __name__ == '__main__':
    main()
