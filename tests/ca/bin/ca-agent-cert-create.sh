#!/bin/bash -ex

echo "Creating agent cert"

# submit a cert request and capture the request ID
pki client-cert-request uid=caagent | tee /tmp/output

sed -n "s/^\s*Request ID:\s*\(\S*\)$/\1/p" /tmp/output > /tmp/request_id
REQUEST_ID=$(cat /tmp/request_id)
echo "- request ID: $REQUEST_ID"

# approve the cert request and capture the cert ID
pki -u caadmin -w Secret.123 ca-cert-request-approve $REQUEST_ID --force | tee /tmp/output

sed -n "s/^\s*Certificate ID:\s*\(\S*\)$/\1/p" /tmp/output > /tmp/cert_id
CERT_ID=$(cat /tmp/cert_id)
echo "- cert ID: $CERT_ID"

# assign the cert to the user
# ignore JSS issue (https://github.com/dogtagpki/jss/issues/781)
pki -u caadmin -w Secret.123 ca-user-cert-add caagent --serial $CERT_ID || true

# import the cert into client
pki client-cert-import caagent --serial $CERT_ID

# test the client certificate
pki -u caagent -w Secret.123 ca-cert-request-find
