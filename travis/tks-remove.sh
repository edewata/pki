#!/bin/bash -ex

pki securitydomain-host-find

pkidestroy -v -i pkitest -s TKS
