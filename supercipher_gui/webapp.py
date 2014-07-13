from flask import Flask, render_template
import threading, json, os, time, platform, sys

app = Flask(__name__, template_folder='./templates')

# log GUI errors to disk
import logging
log_handler = logging.FileHandler('/tmp/supercipher_gui.log')
log_handler.setLevel(logging.WARNING)
app.logger.addHandler(log_handler)

filename = None
is_decrypt = False
pubkey = None

@app.route("/")
def index():
    return render_template('index.html')

