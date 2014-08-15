from PyQt4 import QtCore, QtGui
from supercipher import strings
import common

class Passphrases(QtGui.QVBoxLayout):
    def __init__(self):
        super(Passphrases, self).__init__()

        # passphrase
        passphrase1_label = QtGui.QLabel(strings._('get_passphrase'))
        self.passphrase1_input = QtGui.QLineEdit()
        self.passphrase1_input.setEchoMode(QtGui.QLineEdit.Password)
        passphrase1_layout = QtGui.QHBoxLayout()
        passphrase1_layout.addWidget(passphrase1_label)
        passphrase1_layout.addWidget(self.passphrase1_input)

        # passphrase
        passphrase2_label = QtGui.QLabel(strings._('get_passphrase2'))
        self.passphrase2_input = QtGui.QLineEdit()
        self.passphrase2_input.setEchoMode(QtGui.QLineEdit.Password)
        passphrase2_layout = QtGui.QHBoxLayout()
        passphrase2_layout.addWidget(passphrase2_label)
        passphrase2_layout.addWidget(self.passphrase2_input)

        # add the widgets
        self.addLayout(passphrase1_layout)
        self.addLayout(passphrase2_layout)

