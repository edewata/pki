#!/bin/bash -ex

echo -e "#userspace fips\n" > /etc/system-fips

mkdir -p /var/tmp/userspace-fips
echo -e "1\n" > /var/tmp/userspace-fips/fips-enabled

#chcon -t sysctl_crypto_t -u system_u /var/tmp/userspace-fips/fips-enabled
#chcon --reference=/proc/sys/crypto/fips_enabled /var/tmp/userspace-fips/fips-enabled

mount --bind /var/tmp/userspace-fips/fips-enabled /proc/sys/crypto/fips_enabled

update-crypto-policies --set FIPS
