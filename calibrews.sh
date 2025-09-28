#!/bin/bash
#
export DYNU_API="eV66YVgfd54U32Y2g6T66YUVd473545U"
export SSL_DIR=ssl
export SSL_FULLCHAIN=fullchain.crt
export SSL_PRIVATE_KEY=private/sharpblue_org.key
export CALIBRE_LIBRARY=.

python3 calibrews.py
