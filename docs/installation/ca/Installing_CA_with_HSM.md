Installing CA with HSM
======================

Overview
--------

This page describes the process to install a CA subsystem with a self-signed CA signing certificate
where the system certificates and their keys will be stored in HSM.

CA Subsystem Installation
-------------------------

Prepare a file (e.g. ca-hsm.cfg) that contains the deployment configuration.

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/ca-hsm.cfg](../../../base/server/examples/installation/ca-hsm.cfg).
It assumes that a PKCS #11 token called HSM is available on the system.

Then execute the following command:

```
$ pkispawn -f ca-hsm.cfg -s CA
```

It will install CA subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/ca/alias

Verifying System Certificates
-----------------------------

Verify that the internal token contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
ca_audit_signing                                             ,,P
```

Verify that the HSM contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias -h HSM -f password.txt

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

HSM:ca_signing                                               CTu,Cu,Cu
HSM:ca_ocsp_signing                                          u,u,u
HSM:subsystem                                                u,u,u
HSM:ca_audit_signing                                         u,u,Pu
HSM:sslserver                                                u,u,u
```

Verifying Admin Certificate
---------------------------

Prepare a client NSS database (e.g. ~/.dogtag/nssdb):

```
$ pki -c Secret.123 client-init
```

Import the CA signing certificate:

```
$ pki -c Secret.123 client-cert-import ca_signing --ca-cert ca_signing.crt
```

Import admin key and certificate:

```
$ pki -c Secret.123 client-cert-import \
 --pkcs12 ~/.dogtag/pki-tomcat/ca_admin_cert.p12 \
 --pkcs12-password-file ~/.dogtag/pki-tomcat/ca/pkcs12_password.conf
```

Verify that the admin certificate can be used to access the CA subsystem by executing the following command:

```
$ pki -c Secret.123 -n caadmin ca-user-show caadmin
--------------
User "caadmin"
--------------
  User ID: caadmin
  Full name: caadmin
  Email: caadmin@example.com
  Type: adminType
  State: 1
```
