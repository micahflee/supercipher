import os, sys, subprocess, inspect, platform, argparse, socket, json
from PyQt4 import QtCore, QtGui
from file_selection import FileSelection
import common

try:
    import supercipher
except ImportError:
    sys.path.append(os.path.abspath(common.supercipher_gui_dir+"/.."))
    import supercipher
from supercipher import strings

class Application(QtGui.QApplication):
    def __init__(self):
        self.setAttribute(QtCore.Qt.AA_X11InitThreads, True)
        QtGui.QApplication.__init__(self, sys.argv)

class SuperCipherGui(QtGui.QWidget):
    def __init__(self):
        super(SuperCipherGui, self).__init__()
        self.setWindowTitle('SuperCipher')

        # icon
        self.window_icon = QtGui.QIcon("{0}/icon.png".format(common.supercipher_gui_dir))
        self.setWindowIcon(self.window_icon)

    def start_encrypt(self, encrypt_filenames=None, pubkey=None):
        # file selection
        file_selection = FileSelection()
        # todo: add encrypt_filenames to file_selection

        # main layout
        self.layout = QtGui.QHBoxLayout()
        self.layout.addLayout(file_selection)
        self.setLayout(self.layout)
        self.show()

    def start_decrypt(self, decrypt_filename):
        # label
        label = QtGui.QLabel("Decrypt is not implemented yet")

        # main layout
        self.layout = QtGui.QHBoxLayout()
        self.layout.addWidget(label)
        self.setLayout(self.layout)
        self.show()

    def alert(self, msg, icon=QtGui.QMessageBox.Warning):
        dialog = QtGui.QMessageBox()
        dialog.setWindowTitle("SuperCipher")
        dialog.setWindowIcon(self.window_icon)
        dialog.setText(msg)
        dialog.setIcon(icon)
        dialog.exec_()

def main():
    strings.load_strings(supercipher.supercipher_dir)

    # start the Qt app
    app = Application()

    # clean up when app quits
    def shutdown():
        # nothing to clean up yet
        pass
    app.connect(app, QtCore.SIGNAL("aboutToQuit()"), shutdown)

    # launch the gui
    gui = SuperCipherGui()

    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-e', '--encrypt', metavar='filename', nargs='+', help=strings._('arg_help_encrypt'))
    parser.add_argument('-d', '--decrypt', metavar='filename', dest='decrypt', help=strings._('arg_help_decrypt'))
    parser.add_argument('-p', '--pubkey', metavar='public_key', dest='pubkey', help=strings._('arg_help_pubkey'))
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
    if encrypt_filenames and decrypt_filename:
        gui.alert(strings._('validation_dont_choose_two'))
        sys.exit(0)

    action = 'encrypt'
    if decrypt_filename:
        action = 'decrypt'

    # encrypt validation
    if action == 'encrypt':
        # make sure encrypt_filenames is a list of valid files/folders
        if encrypt_filenames:
            valid = True
            error_msg = ''
            for filename in encrypt_filenames:
                if not os.path.exists(filename):
                    error_msg += strings._('validation_doesnt_exist').format(filename) + '\n\n'
                    valid = False
            if not valid:
                error_msg += strings._('validation_invalid_file')
                gui.alert(error_msg)
                sys.exit(0)

        # if pubkey is passed, make sure the fingerprint is valid
        if pubkey:
            try:
                supercipher.gpg.valid_pubkey(pubkey)
            except InvalidPubkeyLength:
                gui.alert(strings._('validation_pubkey_length'))
                sys.exit(0)
            except InvalidPubkeyNotHex:
                gui.alert(strings._('validation_pubkey_not_hex'))
                sys.exit(0)
            except MissingPubkey:
                gui.alert(strings._('validation_missing_pubkey'))
                sys.exit(0)

    elif action == 'decrypt':
        # make sure decrypt_filename is a valid file
        if decrypt_filename:
            if not os.path.isfile(decrypt_filename):
                gui.alert(strings._('validation_not_file').format(decrypt_filename))
                sys.exit(0)
    
    # execute the action
    if action == 'encrypt':
        gui.start_encrypt(encrypt_filenames, pubkey)
    else:
        gui.start_decrypt(decrypt_filename)

    # all done
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
