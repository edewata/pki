Installing KRA with HSM
=======================

Overview
--------

This page describes the process to install a KRA subsystem
where the system certificates and their keys will be stored in HSM.

KRA Subsystem Installation
--------------------------

Prepare a file (e.g. kra-hsm.cfg) that contains the deployment configuration, for example:

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/kra-hsm.cfg](../../../base/server/examples/installation/kra-hsm.cfg).
It assumes that a PKCS #11 token called HSM is available on the system.

Then execute the following command:

```
$ pkispawn -f kra-hsm.cfg -s KRA
```

It will install KRA subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/kra/alias

Verifying System Certificates
-----------------------------

Verify that the internal token contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
kra_audit_signing                                            ,,P
```

Verify that the HSM contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias -h HSM -f password.txt

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

HSM:kra_transport                                            u,u,u
HSM:kra_storage                                              u,u,u
HSM:subsystem                                                u,u,u
HSM:kra_audit_signing                                        u,u,Pu
HSM:sslserver/server.example.com                             u,u,u
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
 --pkcs12 ca_admin_cert.p12 \
 --pkcs12-password-file pkcs12_password.conf
```

Verify that the admin certificate can be used to access the KRA subsystem by executing the following command:

```
$ pki -c Secret.123 -n caadmin kra-user-show kraadmin
---------------
User "kraadmin"
---------------
  User ID: kraadmin
  Full name: kraadmin
  Email: kraadmin@example.com
  Type: adminType
  State: 1
```

Verifying KRA Connector
-----------------------

Verify that the KRA connector is configured in the CA subsystem:

```
$ pki -c Secret.123 -n caadmin ca-kraconnector-show

Host: server.example.com:8443
Enabled: true
Local: false
Timeout: 30
URI: /kra/agent/kra/connector
Transport Cert:

<base-64 certificate>
```
