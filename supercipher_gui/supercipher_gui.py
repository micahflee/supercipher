import os, sys, subprocess, inspect, platform, argparse, socket, json
from PyQt4 import QtCore, QtGui
from file_selection import FileSelection
import common

try:
    import supercipher
except ImportError:
    sys.path.append(os.path.abspath(common.supercipher_gui_dir+"/.."))
    import supercipher

window_icon = None

class Application(QtGui.QApplication):
    def __init__(self):
        self.setAttribute(QtCore.Qt.AA_X11InitThreads, True)
        QtGui.QApplication.__init__(self, sys.argv)

class SuperCipherGui(QtGui.QWidget):
    def __init__(self):
        super(SuperCipherGui, self).__init__()

    def init_encrypt_ui(self):
        self.setWindowTitle('SuperCipher')

        # icon
        self.window_icon = QtGui.QIcon("{0}/icon.png".format(common.supercipher_gui_dir))
        self.setWindowIcon(self.window_icon)

        # file selection
        file_selection = FileSelection()

        # main layout
        self.layout = QtGui.QHBoxLayout()
        self.layout.addLayout(file_selection)
        self.setLayout(self.layout)
        self.show()

    def alert(self, msg, icon=QtGui.QMessageBox.NoIcon):
        dialog = QtGui.QMessageBox()
        dialog.setWindowTitle("SuperCipher")
        dialog.setWindowIcon(self.window_icon)
        dialog.setText(msg)
        dialog.setIcon(icon)
        dialog.exec_()

def main():
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
    parser.add_argument('-e', '--encrypt', metavar='filename', nargs='+', help='Files and folders to encrypt')
    parser.add_argument('-d', '--decrypt', metavar='filename', dest='decrypt', help='Filename of supercipher file to decrypt')
    parser.add_argument('-p', '--pubkey', metavar='public_key', dest='pubkey', help='Fingerprint of gpg public key to encrypt to')
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

    # display encrypt window
    gui.init_encrypt_ui()

    # all done
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
