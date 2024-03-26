#!/bin/bash

# simple signing script, assumes software key when file id_userca is present,
# YubiHSMs otherwise

export YUBIHSM_PKCS11_CONF=${PWD}/ca/yubihsm_pkcs11.conf
export YHSMP11=/usr/local/lib/pkcs11/yubihsm_pkcs11.dylib

PUBKEY=$1
USER=$2
USERNAME=$(echo $USER | cut -d@ -f1)
# issue user certificate
ssh-keygen -s ./user_ca.pub -D $YHSMP11 -I ${USER} -V +52w -n ${USERNAME},${USER} $PUBKEY
