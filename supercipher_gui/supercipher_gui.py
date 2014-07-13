import os, sys, subprocess, inspect, platform, argparse, socket
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtWebKit import *
import webapp

supercipher_gui_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))

try:
    import supercipher
except ImportError:
    sys.path.append(os.path.abspath(supercipher_gui_dir+"/.."))
    import supercipher

window_icon = None

class Application(QApplication):
    def __init__(self):
        if platform.system() == 'Linux':
            self.setAttribute(Qt.AA_X11InitThreads, True)

        QApplication.__init__(self, sys.argv)

class WebAppThread(QThread):
    def __init__(self, webapp_port):
        QThread.__init__(self)
        self.webapp_port = webapp_port

    def run(self):
        webapp.app.run(port=self.webapp_port)

class Window(QWebView):
    def __init__(self, webapp_port):
        global window_icon
        QWebView.__init__(self)
        self.setWindowTitle("SuperCipher")
        self.resize(400, 300)
        self.setWindowIcon(window_icon)
        self.load(QUrl("http://127.0.0.1:{0}".format(webapp_port)))

def choose_port():
    # let the OS choose a port
    tmpsock = socket.socket()
    tmpsock.bind(("127.0.0.1", 0))
    port = tmpsock.getsockname()[1]
    tmpsock.close()
    return port

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

    # create the icon
    global window_icon, pdfredact_dir
    window_icon = QIcon("{0}/icon.png".format(supercipher_gui_dir))

    # initialize the web app
    webapp.window_icon = window_icon
    webapp.filename = filename
    webapp.is_decrypt = is_decrypt
    webapp.pubkey = pubkey

    # run the web app in a new thread
    webapp_port = choose_port()
    webapp_thread = WebAppThread(webapp_port)
    webapp_thread.start()

    # clean up when app quits
    def shutdown():
        # nothing to clean up yet
        pass
    app.connect(app, SIGNAL("aboutToQuit()"), shutdown)

    # launch the window
    web = Window(webapp_port)
    web.show()

    # all done
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
