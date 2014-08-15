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
        self.init_ui()

    def init_ui(self):
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

def main():
    # start the Qt app
    app = Application()

    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', nargs='?', help='File to encrypt or decrypt')
    parser.add_argument('--decrypt', action='store_true', dest='decrypt', help='Decrypt a supercipher file')
    parser.add_argument('--pubkey', dest='pubkey', help='Fingerprint of gpg public key to encrypt to')
    args = parser.parse_args()

    filename = args.filename
    if filename:
        filename = os.path.abspath(filename[0])
    is_decrypt = bool(args.decrypt)
    pubkey = args.pubkey

    # clean up when app quits
    def shutdown():
        # nothing to clean up yet
        pass
    app.connect(app, QtCore.SIGNAL("aboutToQuit()"), shutdown)

    # launch the gui
    gui = SuperCipherGui()

    # all done
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
