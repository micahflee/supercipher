import os, sys, subprocess, inspect, platform, argparse, socket, json
from PyQt4 import QtCore, QtGui
from file_selection import FileSelection
from passphrases import Passphrases
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
        self.setWindowTitle(strings._('supercipher'))

        # icon
        self.window_icon = QtGui.QIcon("{0}/icon.png".format(common.supercipher_gui_dir))
        self.setWindowIcon(self.window_icon)

    def create_layout(self):
        if not hasattr(self, 'layout'):
            self.layout = QtGui.QVBoxLayout()
            self.setLayout(self.layout)

    def start_choose(self):
        # encrypt button
        self.choose_encrypt_button = QtGui.QPushButton(strings._('gui_encrypt_button'))
        self.choose_encrypt_button.clicked.connect(self.encrypt_clicked)
        self.choose_decrypt_button = QtGui.QPushButton(strings._('gui_decrypt_button'))
        self.choose_decrypt_button.clicked.connect(self.decrypt_clicked)

        # main layout
        self.create_layout()
        self.layout.addWidget(self.encrypt_button)
        self.layout.addWidget(self.decrypt_button)
        self.setLayout(self.layout)
        self.show()

    def remove_choose_widgets(self):
        self.layout.removeItem(self.choose_encrypt_button)
        self.layout.removeItem(self.choose_decrypt_button)

    def encrypt_clicked(self):
        self.remove_choose_widgets()
        self.start_encrypt()
    
    def decrypt_clicked(self):
        self.remove_choose_widgets()
        self.start_decrypt()

    def start_encrypt(self, encrypt_filenames=None, pubkey=None):
        # file selection
        file_selection = FileSelection()
        if encrypt_filenames:
            for filename in encrypt_filenames:
                file_selection.file_list.add_file(filename)

        # passphrases
        passphrases = Passphrases()

        # main layout
        self.create_layout()
        self.layout.addLayout(file_selection)
        self.layout.addLayout(passphrases)
        self.show()

    def start_decrypt(self, decrypt_filename=None):
        # label
        label = QtGui.QLabel("Decrypt is not implemented yet")

        # main layout
        self.create_layout()
        self.layout.addWidget(label)
        self.show()

    def alert(self, msg, icon=QtGui.QMessageBox.Warning):
        dialog = QtGui.QMessageBox()
        dialog.setWindowTitle(strings._('supercipher'))
        dialog.setWindowIcon(self.window_icon)
        dialog.setText(msg)
        dialog.setIcon(icon)
        dialog.exec_()

def main():
    strings.load_strings(supercipher.common.supercipher_dir)

    # start the Qt app
    app = Application()

    # clean up when app quits
    def shutdown():
        # nothing to clean up yet
        pass
    app.connect(app, QtCore.SIGNAL("aboutToQuit()"), shutdown)

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

    if encrypt_filenames:
        action = 'encrypt'
    elif decrypt_filename:
        action = 'decrypt'
    else:
        action = 'none'

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

    # launch the gui
    gui = SuperCipherGui()
    if action == 'none':
        gui.start_choose()
    elif action == 'encrypt':
        gui.start_encrypt(encrypt_filenames, pubkey)
    elif action == 'decrypt':
        gui.start_decrypt(decrypt_filename)

    # all done
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
