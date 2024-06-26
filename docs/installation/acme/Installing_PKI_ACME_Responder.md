Installing PKI ACME Responder
=============================

## Overview

This document describes the process to install an ACME responder on a PKI server that already has a CA subsystem.
It assumes that the CA was [installed](../ca/Installing_CA.md) with the default instance name (i.e. pki-tomcat).

## Installing PKI ACME Responder

To install PKI ACME responder RPM package, execute the following command:

```
$ dnf install pki-acme
```

To create PKI ACME responder in a PKI server instance, execute the following command:

```
$ pki-server acme-create
```

The command will create the initial configuration files in `/var/lib/pki/pki-tomcat/conf/acme` folder.

## Configuring ACME Responder

To configure the ACME responder, see the following documents:

* [Configuring ACME Metadata](Configuring-ACME-Metadata.adoc)
* [Configuring ACME Database](Configuring_ACME_Database.md)
* [Configuring ACME Issuer](Configuring_ACME_Issuer.md)
* [Configuring ACME Realm](Configuring_ACME_Realm.md)

## Deploying ACME Responder

Once everything is ready, deploy the ACME responder with the following command:

```
$ pki-server acme-deploy
```

The command will create a deployment descriptor at `/var/lib/pki/pki-tomcat/conf/Catalina/localhost/acme.xml`.

The server will start the ACME responder automatically in a few seconds.
It is not necessary to restart PKI server.

To verify that the ACME responder is running, execute the following command:

```
$ curl -s -k https://$HOSTNAME:8443/acme/directory | python -m json.tool
{
    "meta": {
        "caaIdentities": [
            "example.com"
        ],
        "externalAccountRequired": false,
        "termsOfService": "https://www.example.com/acme/tos.pdf",
        "website": "https://www.example.com"
    },
    "newAccount": "https://<hostname>:8443/acme/new-account",
    "newNonce": "https://<hostname>:8443/acme/new-nonce",
    "newOrder": "https://<hostname>:8443/acme/new-order",
    "revokeCert": "https://<hostname>:8443/acme/revoke-cert"
}
```

## Undeploying ACME Responder

To undeploy the ACME responder, execute the following command:

```
$ pki-server acme-undeploy
```

The command will remove the deployment descriptor at `/var/lib/pki/pki-tomcat/conf/Catalina/localhost/acme.xml`.

The server will stop the ACME responder automatically in a few seconds.
It is not necessary to restart PKI server.

To restart the ACME responder, execute `pki-server acme-deploy` again.

## Removing ACME Responder

To remove the ACME responder completely from the server, execute the following command:

```
$ pki-server acme-remove
```

## See Also

* [Installing CA](../ca/Installing_CA.md)
* [Managing PKI ACME Responder](../../admin/acme/Managing_PKI_ACME_Responder.md)
* [Using PKI ACME Responder](../../user/acme/Using_PKI_ACME_Responder.md)
* [pki-server-acme(8)](../../manuals/man8/pki-server-acme.8.md)
