import os, inspect, platform

if platform.system() == 'Darwin':
    supercipher_gui_dir = os.path.dirname(__file__)
else:
    supercipher_gui_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
