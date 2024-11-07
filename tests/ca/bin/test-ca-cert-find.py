#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import argparse
import logging

import pki.ca
import pki.cert
import pki.client

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(levelname)s: %(message)s')

parser = argparse.ArgumentParser()
parser.add_argument(
    '-U',
    '--url',
    help='Server URL')
parser.add_argument(
    '--cert-paths',
    help='Path to CA certificates')
parser.add_argument(
    '--api',
    help='API version: v1, v2')
parser.add_argument(
    '-v',
    '--verbose',
    help='Run in verbose mode.',
    action='store_true')
parser.add_argument(
    '--debug',
    help='Run in debug mode.',
    action='store_true')

args = parser.parse_args()

if args.debug:
    logging.getLogger().setLevel(logging.DEBUG)

elif args.verbose:
    logging.getLogger().setLevel(logging.INFO)

pki_client = pki.client.PKIClient(
    url=args.url,
    cert_paths=args.cert_paths,
    api=args.api)

ca_client = pki.ca.CAClient(pki_client)
cert_client = pki.cert.CertClient(ca_client)

cert_infos = cert_client.list_certs()

first = True

for cert_info in cert_infos:

    if first:
        first = False
    else:
        print()

    print('  Serial Number: ' + cert_info.serial_number)
    print('  Subject DN: ' + cert_info.subject_dn)
    print('  Status: ' + cert_info.status)
