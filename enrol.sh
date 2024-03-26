#!/bin/bash

# NOTE: proof-of-concept: tested on macos only!

# simple CA client to obtain an SSH certificate from an online CA
# the CA requires an ID token and an attestation from a hardware security key
# the public key in the attestation is cryptographically bound to the ID token

set -e
[ ! -z "$DEBUG" ] && set -x

# check for non-default tools
command -v jq >/dev/null || { echo please install jq first; exit; }
command -v step >/dev/null || { echo please install step first; exit; }
command -v trurl >/dev/null || { echo please install trurl first; exit; }

# load client configuration with OIDC_CONF, CLIENT_ID, CA, etc
. enrol.conf

### STEP 1: generate an SSH key pair backed by a FIDO security key

# defaults:
: "${APPLICATION:=ssh:}"
: "${KEYTYPE:=ecdsa-sk}"
KEYFILE="id_${KEYTYPE//-sk/_sk}"

# generate a new SSH key, unless one already exists
if [[ ! -f "./$KEYFILE" ]] ; then
  echo "❗ no pubkey file found - generating new key"
  openssl rand 128 > challenge.bin
  ssh-keygen -t ${KEYTYPE} -f ./$KEYFILE -N "" -C "" -O resident -O user=$USER -O write-attestation=attestation.bin -O application="${APPLICATION}" -O challenge=challenge.bin
fi

### STEP 2: obtain an ID token bound to the public key

# we cannot simply call "step oauth --oidc --bare", as we want to set a custom nonce

# defaults:
: "${OIDC_OP:=https://accounts.google.com}"

# retrieve IDP config
OIDC_CONF=$(curl -s $OIDC_OP/.well-known/openid-configuration)

ISSUER=$(<<<"$OIDC_CONF" jq --raw-output .issuer)
AUTHZ_URL=$(<<<"$OIDC_CONF" jq --raw-output .authorization_endpoint)
TOKEN_URL=$(<<<"$OIDC_CONF" jq --raw-output .token_endpoint)
JWKS=$(<<<"$OIDC_CONF" jq --raw-output .jwks_uri)

#### STEP 2a: obtain authorization code

# Use PKCE to prevent authorization code injection attacks:
CODE_VERIFIER=$(cat /dev/random | head -c24 | xxd -p)
CODE_CHALLENGE=$(echo -n $CODE_VERIFIER | openssl dgst -sha256 -binary | base64 | tr '/+' '_-' | sed 's/=*$//')

# State is normally used for CSRF, but here we use PKCE for that, so we use a dummy state
STATE=dummy

# use the public key hash as the nonce - a simplification from OpenPubKey
NONCE=$(ssh-keygen -lf ./$KEYFILE.pub | awk '{print $2}' | cut -d: -f2 | xargs -IX echo X= | base64 -d | basenc --base64url)

# Initiate authorization code flow:
open $(trurl --url $AUTHZ_URL?scope=openid+email \
	--append query=response_type=code \
	--append query=client_id=$CLIENT_ID \
	--append query=state=$STATE \
	--append query=redirect_uri=$REDIRECT_URI \
	--append query=code_challenge=$CODE_CHALLENGE \
	--append query=code_challenge_method=S256 \
	--append query=nonce=$NONCE)

# HTTP listener on localhost redirect_uri to extract the request target from the HTTP request line (GET TARGET HTTP/1.1)
while [[ -z "$TARGET" ]]; do
  TARGET=$(echo -e "HTTP/1.1 200 OK\n\nSuccess - please close this browser window and return to your client" \
       | /usr/bin/nc -l $PORT | head -1 | cut -d' ' -f2)
  echo .
done

# extract the authorization code from the target request query parameters
AUTHORIZATION_CODE=$(trurl "http://localhost$TARGET" -g '{query:code}')
[[ -z "$AUTHORIZATION_CODE" ]] && { echo "❌ ERROR receiving authorization code"; exit; }
echo "✅ recieved authorization"
# ignoring state here...

#### STEP 2b: exchange authorization code from an ID token

# Exchange authorization code for an ID token:
TOKEN=$( \
  curl -sX POST $TOKEN_URL \
    -d grant_type=authorization_code \
    -d redirect_uri=$REDIRECT_URI \
    -d client_id=$CLIENT_ID \
    -d client_secret=$CLIENT_SECRET \
    -d code_verifier=$CODE_VERIFIER \
    -d code=$AUTHORIZATION_CODE \
)

jq --raw-output .id_token <<<"$TOKEN" >idtoken.jwt
echo "✅ saved ID token in idtoken.jwt"

### STEP 3: obtain a certificate signing request from the online CA

# verify ID token
VERIFIED=$(step crypto jwt verify --jwks $JWKS --iss $ISSUER --aud $CLIENT_ID < idtoken.jwt)

# extract email and username from verified ID token
EMAIL=$(jq --raw-output .payload.email <<<"$VERIFIED")
echo "✅ requesting an SSH certificate for $EMAIL"
USERNAME=$(cut -d@ -f1 <<<"$EMAIL")

# request certificates from CA
OUTFILE=$(mktemp -t $KEYFILE)
STATUS=$(curl --silent $CA \
	--data-urlencode idtoken@idtoken.jwt \
	--data-urlencode pubkey@$KEYFILE.pub \
	--expand-variable challenge@challenge.bin \
	--expand-data-urlencode challenge="{{challenge:b64}}" \
	--expand-variable attestation@attestation.bin \
	--expand-data-urlencode attestation="{{attestation:b64}}" \
	--output $OUTFILE \
	--write-out '%{http_code}' \
)

if [[ "200" != "$STATUS" ]] ; then
	echo -n "❌ ERROR: "
	# show error message instead of certificate
	cat $OUTFILE; echo
	exit
fi

CERTFILE=$KEYFILE-cert.pub
PROVISIONERFILE=$KEYFILE-provisioner-cert.pub
grep openssh $OUTFILE | sed -n 1p > $CERTFILE
grep openssh $OUTFILE | sed -n 2p > $PROVISIONERFILE

echo "✅ certificate saved to file $CERTFILE"
echo "✅ to inspect your certificate:"
echo "  ssh-keygen -f $CERTFILE -L"
echo "✅ to inspect your provisioning certificate:"
echo "  ssh-keygen -f $PROVISIONERFILE -L"

echo "✅ To create an account using your provisioning certificate:"
echo "  ssh -i $KEYFILE -o CertificateFile=$PROVISIONERFILE root@localhost"

echo "✅ To logon using your certificate:"
echo "  ssh -i $KEYFILE $USERNAME@localhost"
