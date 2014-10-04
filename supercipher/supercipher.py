import os, sys, argparse
from gnupg import InvalidPubkeyLength, InvalidPubkeyNotHex, MissingPubkey, MissingSeckey
from scfile import SuperCipherFile, InvalidSuperCipherFile, FutureFileVersion, InvalidArchive, InvalidDecryptionPassphrase

import strings, helpers, common

def encrypt(filenames, output_filename, pubkey=None, passphrase=None):
    print strings._('encrypt_encrypting_files').format(filenames)

    if not passphrase:
        passphrase = helpers.get_passphrase(True)

    scf = SuperCipherFile()
    try:
        scf.lock(output_filename, filenames, passphrase, pubkey)
    except KeyboardInterrupt:
        print strings._('cleanup')

def decrypt(filename, output_dir, passphrase=None):
    print strings._('decrypt_decrypting_file').format(filename)

    if not passphrase:
        passphrase = helpers.get_passphrase()

    scf = SuperCipherFile()
    try:
        scf.unlock(output_dir, filename, passphrase)
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

def main():
    strings.load_strings(common.supercipher_dir)

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
            try:
                common.gpg.valid_pubkey(pubkey)
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
