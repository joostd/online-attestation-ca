import argparse
import base64
import subprocess
import tempfile
from struct import unpack
from hashlib import sha256
import jwt
import requests
import os

from fido2 import cbor, mds3, webauthn, cose
from cryptography import x509, exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519

from flask import Flask, request, jsonify, abort, make_response

issuer = 'https://accounts.google.com'
oidc_url = f"{issuer}/.well-known/openid-configuration"

# read a list of type-lenght-value triplets from binary data
def tlvs(data):
    while data:
        t, l = unpack('>hh', data[:4])
        assert t == 0
        v = data[4:4+l]
        data = data[4+l:]
        yield v

# attestation information format, see
# https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
#
# string		"ssh-sk-attest-v01"
# string		attestation certificate
# string		enrollment signature
# string		authenticator data (CBOR encoded)
# uint32		reserved flags
# string		reserved string

# NOTE: there is currently a feature missing in libfido2 preventing clients like ssh-keygen to obtain intermediate certificates
#       from a FIDO attestation statement. Consequently, attestation certificate validation only works for security keys
#       with attestation certificates that are direcly issued by a root certificate registered in MDS

# parse SSH attestation file 
def parseAttestation(s):
    version, certificate, signature, authData, reserved_flags, reserved_string  = tlvs(s)
    version = str(version, 'utf-8')
    assert version == 'ssh-sk-attest-v01'
    certificate = x509.load_der_x509_certificate(certificate)
    authData = cbor.decode(authData)
    assert reserved_flags== b''
    assert reserved_string == b''
    return dict( version=version, certificate=certificate, signature=signature, authData=authData)

def verifyAttestation(attestation, challenge):
    authData = attestation['authData']
    clientDataHash = sha256(challenge).digest()
    signedData = b''.join([authData, clientDataHash])
    signature = attestation['signature']
    attestation_certificate = attestation['certificate']
    assert isinstance( attestation_certificate.public_key(), ec.EllipticCurvePublicKey )
    attestation_certificate.public_key().verify(signature, signedData, ec.ECDSA(hashes.SHA256()))

def verifyAttestationU2F(attestation, challenge):
    authData = webauthn.AuthenticatorData(attestation['authData'])
    credentialData = authData.credential_data
    key = b''.join([b'\04', credentialData.public_key[-2], credentialData.public_key[-3]])
    signedData = b''.join([b'\00', authData.rp_id_hash, sha256(challenge).digest(), credentialData.credential_id, key])
    signature = attestation['signature']
    attestation_certificate = attestation['certificate']
    assert isinstance( attestation_certificate.public_key(), ec.EllipticCurvePublicKey )
    attestation_certificate.public_key().verify(signature, signedData, ec.ECDSA(hashes.SHA256()))

# parse SSH pubkey file
# https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f

def parsePubkey(key):
    key_type, pubkey, *_ = key.split(" ")
    key=base64.b64decode(pubkey)
    match key_type:
        # The format of a sk-ecdsa-sha2-nistp256@openssh.com public key is:
        #	string		"sk-ecdsa-sha2-nistp256@openssh.com"
        #	string		curve name
        #	ec_point	Q
        #	string		application (user-specified, but typically "ssh:")
        case 'sk-ecdsa-sha2-nistp256@openssh.com':
            (kt,curve_name,ec_point,*application) = tlvs(key)
            assert str(kt,'utf-8') == key_type
            publicKey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ec_point)
            return cose.ES256.from_cryptography_key(publicKey)
        # The format of a sk-ssh-ed25519@openssh.com public key is:
        #	string		"sk-ssh-ed25519@openssh.com"
        #	string		public key
        #	string		application (user-specified, but typically "ssh:")
        case 'sk-ssh-ed25519@openssh.com':
            (kt,pk,*application) = tlvs(key)
            assert str(kt,'utf-8') == key_type
            publicKey = ed25519.Ed25519PublicKey.from_public_bytes(pk)
            return cose.EdDSA.from_cryptography_key(publicKey)
        case _:
            raise Exception('unsupported SSH key type')

# the fido alliance metadata URL
mdsurl = 'https://mds3.fidoalliance.org/'
# the root CA used to verify the FIDO Metadata Statement blob
MDS_CA = base64.b64decode(
    """
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4
MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8
RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT
gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm
KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd
QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ
XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o
LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU
RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp
jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK
6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX
mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs
Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH
WD9f"""
)

def getMetadata(file):
    with open(file, "rb") as f:
      data = f.read()
      return mds3.parse_blob(data, MDS_CA)

# verify if an SSH key has hardware key protection by verifying its attestation
# only works for SSH keys backed by FIDO security keys
#
# procedure - given an SSH public key and its attestation:
# 1. verify attestation signature using attestation certificate
# 2. match SSH public key with key in attestation
# 3. extract AAGUID and lookup authenticator metadata using FIDO Metadata Service
# 4. validate attestation certificate using registered root certificates,
#    or using provided issuer certificate
# 5. check metadata for hardware and secure_element key protection
# 6. check metadata for on_chip matcher protection

def verify(publicKey, attestation, challenge):
  # verify attestation signature, assuming packed attestation
  try:
    verifyAttestation(attestation, challenge) 
  except AssertionError:
    abort(make_response(f"Attestation certificate uses an unsupported key type", 400))
  except exceptions.InvalidSignature:
    # Invalid packed attestation signature, retry with fido-u2f
    try:
      verifyAttestationU2F(attestation, challenge) 
    except exceptions.InvalidSignature:
      abort(make_response("Invalid attestation signature, or unsupported attestation format", 400))

  # match public keys
  credentialData = webauthn.AuthenticatorData(attestation['authData']).credential_data
  if credentialData.public_key != publicKey:
    abort(make_response(f"Public key in does not match public key in attestation", 400))

  # lookup metadata in MDS
  metadata_entry = None
  try:
    if(credentialData.aaguid == webauthn.Aaguid.NONE):
        abort(make_response('No AAGUID present in attestation, cannot lookup metadata', 400))
    else:
      metadata = getMetadata(args.mds_file)
      metadata_entry = mds3.MdsAttestationVerifier(metadata).find_entry_by_aaguid(credentialData.aaguid)
  except ValueError:
    abort(make_response(f"FIDO Metadata file malformed ({args.mds_file})", 400))
  except FileNotFoundError:
    abort(make_response(f"FIDO Metadata file not found ({args.mds_file})", 400))

  # validate attestation certificate
  try:
    attestation_certificate = attestation['certificate']
    # validate attestation certificate using registered root certificates
    if metadata_entry:	# use roots from MDS
      issuers = [ x509.load_der_x509_certificate(cert, default_backend()) for cert in metadata_entry.metadata_statement.attestation_root_certificates ]
    else:	# no issuers, fail
      issuers = []
    trusted = False
    for cert in issuers:
      if cert.subject == attestation_certificate.issuer:
        attestation_certificate.verify_directly_issued_by(cert)
        trusted = True
    if not trusted:
      abort(make_response(f"Cannot validate attestation certificate ({attestation_certificate.subject.rfc4514_string({x509.oid.NameOID.EMAIL_ADDRESS: 'E'})}) is not signed by a trusted issuer", 400))
  except exceptions.InvalidSignature:
    abort(make_response('Invalid signature on attestation certificate', 400))
  except ValueError:
    abort(make_response(f"Invalid issuer certificate ({cert.subject.rfc4514_string({x509.oid.NameOID.EMAIL_ADDRESS: 'E'})})", 400))
  except TypeError:
    abort(make_response(f"Unsupported issuer public key type ({cert.public_key()})", 400))

  if metadata_entry:
    status_list = [s.status for s in metadata_entry.status_reports]
    if 'FIDO_CERTIFIED' not in status_list:
      abort(make_response(f"Security key is not FIDO certified ({ ', '.join(status_list) })", 400))

    # https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#key-protection-types
    # software, hardware, tee, secure_element, remote_handle
    if 'hardware' in metadata_entry.metadata_statement.key_protection:
      if 'secure_element' not in metadata_entry.metadata_statement.key_protection:
        app.logger.info(f"➖ security key has hardware key protection but not using a secure element ({metadata_entry.metadata_statement.key_protection})")
    else:
      app.logger.info(f"➖ security key has no hardware key protection ({metadata_entry.metadata_statement.key_protection})")

    # https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#matcher-protection-types
    # software, tee, on_chip
    if 'on_chip' not in metadata_entry.metadata_statement.matcher_protection:
      app.logger.info(f"➖ security key has no on_chip matcher protection ({metadata_entry.metadata_statement.key_protection})")

  if metadata_entry:
    app.logger.info(f"valid attestation for hardware authenticator ({credentialData.aaguid}): {metadata_entry.metadata_statement.description}")
  else:
    app.logger.info(f"valid attestation for unknown authenticator")
  return True

def verifyID(client_id, id_token):
  oidc_config = requests.get( oidc_url ).json()
  signing_algos = oidc_config["id_token_signing_alg_values_supported"]
  # setup a PyJWKClient to get the appropriate signing key
  jwks_client = jwt.PyJWKClient(oidc_config["jwks_uri"])
  # get signing_key from id_token
  signing_key = jwks_client.get_signing_key_from_jwt(id_token)
  try:
    data = jwt.decode(
      id_token,
      key=signing_key.key,
      algorithms=signing_algos,
      audience=client_id,
      options={"verify_exp": True},
    )
  except jwt.exceptions.InvalidAudienceError:
    abort(make_response("ID token audience does not match", 400))
  except jwt.exceptions.ExpiredSignatureError:
    abort(make_response("ID token has expired", 400))
  return data


def issue(pubkey, user):
  cert = None
  with tempfile.NamedTemporaryFile() as fp:
    fp.write(str.encode(pubkey))
    fp.flush()
    certfilename = f'{fp.name}-cert.pub'
    # issue certificate
    result = subprocess.run(['/bin/sh', './issue.sh', fp.name, user])
    if result.returncode==0:
      try:
        with open(certfilename, mode='r') as f:
          cert = f.read()
      except FileNotFoundError:
        abort(make_response(f"SSH certificate file not found ({fp.name}", 500))
    else:
      abort(make_response("Issuing process failed", 500))
    # also issue a provisioning certificate
    result = subprocess.run(['/bin/sh', './issue-provisioner.sh', fp.name, user])
    if result.returncode==0:
      try:
        with open(certfilename, mode='r') as f:
          provisioner = f.read()
      except FileNotFoundError:
        abort(make_response(f"SSH certificate file not found ({fp.name}", 500))
    else:
      abort(make_response("Issuing process failed", 500))
    fp.close()
  # file is automatically removed
  return cert+provisioner

# check if public key is bound to ID token
# TODO: comply with OpenPubKey spec - using a simpler (and less secure) binding here for demo purposes
def isBound(pubkey, nonce):
  key = base64.b64decode(pubkey.split(" ")[1]) 
  h = sha256(key).digest() 
  nonce= base64.urlsafe_b64decode(nonce)
  return nonce == h

# process command line arguments
parser = argparse.ArgumentParser(description='evaluate an SSH SK attestation')
parser.add_argument('-m', '--mds', dest='mds_file', default = 'mds.jwt', help='specify MDS JWT file')
parser.add_argument('-d', '--domain', dest='domain', default = 'yubico.com', help='specify OpenID Provider domain')
parser.add_argument('-c', '--client', dest='client_id', default = os.environ["CLIENT_ID"], help='specify OpenID client ID')

args = parser.parse_args()

app = Flask(__name__)
app.logger.info(f"starting CA using client ID {args.client_id}")

@app.route('/', methods=['GET'])
def get():
  return 'demo CA - POST your SSH certificate signing request here!'

@app.route('/', methods=['POST'])
def post():
  # challenge used when creating FIDO credential
  challenge = request.form.get("challenge")
  if challenge is None:
    abort(make_response("challenge parameter required", 400))
  challenge = base64.urlsafe_b64decode(challenge)
  # SSH key attestation
  attestation = request.form.get("attestation")
  if attestation is None:
    abort(make_response("attestation parameter required", 400))
  try:
    attestation = parseAttestation(base64.urlsafe_b64decode(attestation))
  except AssertionError:
    abort(make_response(f"Attestation malformed ({attestation})", 400))
  # OIDC idtoken
  idtoken = request.form.get("idtoken").strip()
  if idtoken is None:
    abort(make_response("idtoken parameter required", 400))
  data = verifyID(args.client_id, idtoken)
  app.logger.info(f"Verified identity {data['email']}")
  assert data['email_verified'] == True
  user = data['email']
  assert data['hd'] == args.domain
  # SSH public key
  pubkey = request.form.get("pubkey")
  if pubkey is None:
    abort(make_response("pubkey parameter required", 400))
  try:
    publicKey = parsePubkey(pubkey)
  except AssertionError:
    abort(make_response(f"SSH pubkey file malformed ({pubkey})", 400))
  except Exception as e:
    abort(make_response(f"{e}", 400))
  # check is ID token is bound to pubkey
  if 'nonce' not in data:
    abort(make_response("nonce missing from ID token", 400))
  nonce = data['nonce']
  if not isBound(pubkey,nonce):
    abort(make_response("Public key is not bound to ID token", 400))
  # verify attestation for publicKey
  if not verify(publicKey, attestation, challenge):
    abort(make_response("attestation validation failed", 400))
  cert = issue(pubkey, user)
  if cert is None:
    abort(make_response("Issuing process failed", 500))
  return cert
  
if __name__ == '__main__':
    app.run(host='0.0.0.0', port='8000', debug=True)
