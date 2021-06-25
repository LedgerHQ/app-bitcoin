btchip-python
=============

Python communication library for Ledger Hardware Wallet products  

Requirements
-------------

This API is available on pip - install with pip install btchip-python 

Building on a Unix platform requires libusb-1.0-0-dev and libudev-dev installed previously

Interim Debian packages have also been built by Richard Ulrich at https://launchpad.net/~richi-paraeasy/+archive/ubuntu/bitcoin/ (btchip-python, hidapi and python-hidapi)

For optional BIP 39 support during dongle setup, also install https://github.com/trezor/python-mnemonic - also available as a Debian package at the previous link (python-mnemonic)

Building on Windows
--------------------

  - Download and install the latest Python 2.7 version from https://www.python.org/downloads/windows/
  - Install Microsoft Visual C++ Compiler for Python 2.7 from http://www.microsoft.com/en-us/download/details.aspx?id=44266
  - Download and install PyQt4 for Python 2.7 from https://www.riverbankcomputing.com/software/pyqt/download 
  - Install the btchip library (open a command prompt and enter c:\python27\scripts\pip install btchip)
  
Building/Installing on FreeBSD
------------------------------
  
On FreeBSD you can install the packages:

    pkg install security/py-btchip-python

or build via ports:

    cd /usr/ports/security/py-btchip-python
    make install clean

  
