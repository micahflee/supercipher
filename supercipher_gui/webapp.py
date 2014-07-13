import threading, json, os, time, platform, sys
from flask import Flask, render_template
from PyQt4.QtGui import *

app = Flask(__name__, template_folder='./templates')

# log GUI errors to disk
import logging
log_handler = logging.FileHandler('/tmp/supercipher_gui.log')
log_handler.setLevel(logging.WARNING)
app.logger.addHandler(log_handler)

filename = None
is_decrypt = False
pubkey = None
window_icon = None

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/encrypt")
def encrypt():
    return render_template('encrypt.html')

@app.route("/decrypt")
def decrypt():
    return render_template('decrypt.html')

@app.route('/select_file')
def select_file():
    # TODO: deal with Qt error
    # QObject: Cannot create children for a parent that is in a different thread.
    filename = QFileDialog.getOpenFileName(caption='Select file', options=QFileDialog.ReadOnly)
    if not filename:
        return json.dumps({ 'error': True, 'error_type': 'canceled' })

    filename = str(filename)
    if not os.path.isfile(filename):
        return json.dumps({ 'error': True, 'error_type': 'invalid' })

    filename = os.path.abspath(filename)
    basename = os.path.basename(filename)
    return json.dumps({ 'error': False, 'filename': filename, 'basename': basename })

