#!/bin/bash -ex

pkispawn -v -f ${BUILDDIR}/pki/travis/pki.cfg -s CA

pki-server cert-export ca_signing -i pkitest --cert-file ca_signing.crt
pki client-cert-import --ca-cert ca_signing.crt
