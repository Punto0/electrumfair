#!/usr/bin/env python2
# -*- coding: UTF8 -*-
# python setup.py sdist --format=zip,gztar

from setuptools import setup
import os
import sys
import platform
import imp
import argparse

version = imp.load_source('version', 'lib/version.py')

if sys.version_info[:3] < (2, 7, 0):
    sys.exit("Error: ElectrumFair requires Python version >= 2.7.0...")

data_files = []

if platform.system() in ['Linux', 'FreeBSD', 'DragonFly']:
    parser = argparse.ArgumentParser()
    parser.add_argument('--root=', dest='root_path', metavar='dir', default='/')
    opts, _ = parser.parse_known_args(sys.argv[1:])
    usr_share = os.path.join(sys.prefix, "share")
    if not os.access(opts.root_path + usr_share, os.W_OK) and \
       not os.access(opts.root_path, os.W_OK):
        if 'XDG_DATA_HOME' in os.environ.keys():
            usr_share = os.environ['XDG_DATA_HOME']
        else:
            usr_share = os.path.expanduser('~/.local/share')
    data_files += [
        (os.path.join(usr_share, 'applications/'), ['electrumfair.desktop']),
        (os.path.join(usr_share, 'pixmaps/'), ['icons/electrumfair.png'])
    ]

setup(
    name="ElectrumFair",
    version=version.ELECTRUMFAIR_VERSION,
    install_requires=[
        'slowaes>=0.1a1',
        'ecdsa>=0.9',
        'pbkdf2',
        'requests',
        'qrcode',
        'protobuf',
        'dnspython',
        'jsonrpclib',
    ],
    packages=[
<<<<<<< HEAD
        'electrumfair',
        'electrumfair_gui',
        'electrumfair_gui.qt',
        'electrumfair_plugins',
        'electrumfair_plugins.audio_modem',
        'electrumfair_plugins.cosigner_pool',
        'electrumfair_plugins.email_requests',
        'electrumfair_plugins.exchange_rate',
        'electrumfair_plugins.greenaddress_instant',
        'electrumfair_plugins.hw_wallet',
        'electrumfair_plugins.keepkey',
        'electrumfair_plugins.labels',
        'electrumfair_plugins.ledger',
        'electrumfair_plugins.plot',
        'electrumfair_plugins.trezor',
        'electrumfair_plugins.trustedcoin',
        'electrumfair_plugins.virtualkeyboard',
=======
        'electrum',
        'electrum_gui',
        'electrum_gui.qt',
        'electrum_plugins',
        'electrum_plugins.audio_modem',
        'electrum_plugins.cosigner_pool',
        'electrum_plugins.email_requests',
        'electrum_plugins.greenaddress_instant',
        'electrum_plugins.hw_wallet',
        'electrum_plugins.keepkey',
        'electrum_plugins.labels',
        'electrum_plugins.ledger',
        'electrum_plugins.trezor',
        'electrum_plugins.trustedcoin',
        'electrum_plugins.virtualkeyboard',
>>>>>>> electrum-2.7.13
    ],
    package_dir={
        'electrumfair': 'lib',
        'electrumfair_gui': 'gui',
        'electrumfair_plugins': 'plugins',
    },
    package_data={
        'electrumfair': [
            'www/index.html',
            'wordlist/*.txt',
            'locale/*/LC_MESSAGES/electrum.mo',
        ]
    },
    scripts=['electrumfair'],
    data_files=data_files,
    description="Lightweight FairCoin Wallet",
    author="Thomas Voegtlin, Thomas König",
    author_email="thomasv@electrum.org, tom@fair-coin.org",
    license="MIT Licence",
    url="https://electrum.fair-coin.org",
    long_description="""Lightweight FariCoin Wallet"""
)
