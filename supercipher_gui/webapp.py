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

qtstuff = None
qtstuff_return = None

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
    global qtstuff, qtstuff_return
    qtstuff.select_file.emit()
    return qtstuff_return

