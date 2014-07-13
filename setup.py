import os, sys, platform

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

version = open('supercipher/version').read().strip()

setup(
    name='supercipher',
    version=version,
    author='Micah Lee',
    author_email='micah@micahflee.com',
    platforms=['GNU/Linux'],
    license='GPLv3',
    description='Encrypts a file with a passphrase using several ciphers',
    long_description="""
Supercipher encrypts a file with a passphrase and optionally a GPG public key.

It stretches the passphrase into several keys (using multiple key derivation functions) and encrypts the file several times using different ciphers and keys each time. In this way, an attacker needs to know of weaknesses in all key derivation functions or all ciphers rather than just one to successfully do a crypto attack against it.

If you supply a public key, it encrypts the file one final time using public key encryption, requiring both the public key and passphrase to decrypt.
    """,
    packages=['supercipher', 'supercipher_gui'],
    include_package_data=True,
    scripts=['bin/supercipher', 'bin/supercipher-gui'],
    data_files=[
        ('/usr/share/applications', ['install/supercipher.desktop']),
        ('/usr/share/pixmaps', ['install/supercipher.xpm'])
    ]
)
