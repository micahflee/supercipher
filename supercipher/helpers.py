import os, hashlib, base64, shutil, getpass, tarfile
import strings

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
        print strings._('mkdir_error').format(tmp_dir)
        return False

def destroy_tmp_dir(tmp_dir):
    shutil.rmtree(tmp_dir, ignore_errors=True)

def get_passphrase(ask_twice=False):
    if ask_twice:
        valid_passphrase = False
        while not valid_passphrase:
            passphrase = getpass.getpass(strings._('get_passphrase'))
            passphrase2 = getpass.getpass(strings._('get_passphrase2'))
            if passphrase == passphrase2:
                valid_passphrase = True
            else:
                print strings._('passphrase_mismatch')
    else:
        passphrase = getpass.getpass(strings._('get_passphrase'))

    return passphrase

# compress the plaintext file, preserving its filename
def compress(filenames, archive_filename):
    print strings._('compressing')

    def reset(tarinfo):
        strip_dir = False
        absfilename = '/{0}'.format(tarinfo.name)
        for filename in filenames:
            if os.path.isdir(filename) and absfilename.startswith(filename):
                strip_dir = True
                tarinfo.name = tarinfo.name[len(os.path.dirname(filename)):]

        if not strip_dir:
            tarinfo.name = os.path.basename(tarinfo.name)

        #print strings._('adding').format(tarinfo.name)

        tarinfo.uid = tarinfo.gid = 0
        tarinfo.uname = tarinfo.gname = "root"
        return tarinfo

    with tarfile.open(archive_filename, 'w:gz') as tar:
        for filename in filenames:
            tar.add(filename, recursive=True, filter=reset)

