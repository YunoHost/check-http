# check-http

This is a HTTP server that allow a YunoHost instance to check if it can be
reached by HTTP from outside before trying to generate a LE certificate.

This is done because some network configration prevent HTTP loopback.

# Installation

This is a travial python 3 (yes 3) project to install, juste create a
virtualenv, install the content of the requirements.txt (there is a "-frozen"
version if need) and do `python server.py`. No other configuration/db needed.
