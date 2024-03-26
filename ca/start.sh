#!/bin/bash

export YUBIHSM_PKCS11_CONF=${PWD}/yubihsm_pkcs11.conf
export YHSMP11=/usr/local/lib/pkcs11/yubihsm_pkcs11.dylib

curl --fail-with-body http://localhost:12345/connector/status \
	|| { echo start HSM first; exit; }

yubihsm-shell --authkey 1 -p password -a get-public-key -i 0x2222 \
	|| yubihsm-shell --authkey 1 -p password -a generate-asymmetric-key -i 0x2222 -l sshca -d 1 -c sign-ecdsa -A ecp256

[[ -f ./user_ca.pub ]] \
	|| ssh-keygen -D $YHSMP11 > ./user_ca.pub

[[ -f ./mds.jwt ]] \
	|| curl https://mds3.fidoalliance.org -L --output mds.jwt

[[ -f ./venv ]] \
	|| python3 -m venv ./venv

python3 -c 'import sys; exit(sys.prefix == sys.base_prefix)' \
        || . venv/bin/activate

pip install -r requirements.txt

export CLIENT_ID=823225820882-sp7oj9quuvoc94nat5s31joqg90e85mc.apps.googleusercontent.com

export DISPLAY=:
export SSH_ASKPASS=$PWD/askpass.sh 
export SSH_ASKPASS_REQUIRE=force

python app.py
