Deploying PKI CA on OpenShift
=============================

## Overview

This document describes the process to deploy PKI CA as a container on OpenShift.
The container image is available at [quay.io/dogtagpki/pki-ca](https://quay.io/repository/dogtagpki/pki-ca).

By default the responder will use a temporary CA signing certificate.
A new self-signed CA certificate will be created every time the responder is restarted.
It is possible to replace it with a permanent CA signing certificate.

By default the responder will use a temporary database.
A new empty in-memory database will be created every time the responder is restarted.
It is possible to replace it with a permanent database.

By default the responder will use a temporary realm.
A new empty in-memory realm will be created every time the responder is restarted.
It is possible to replace it with a permanent realm.

## Deploying PKI CA

A sample configuration for PKI CA is available at:

- [/usr/share/pki/ca/openshift/pki-ca-certs.yaml](../../../base/ca/openshift/pki-ca-certs.yaml)
- [/usr/share/pki/ca/openshift/pki-ca-database.yaml](../../../base/ca/openshift/pki-ca-database.yaml)
- [/usr/share/pki/ca/openshift/pki-ca-realm.yaml](../../../base/ca/openshift/pki-ca-realm.yaml)
- [/usr/share/pki/ca/openshift/pki-ca-is.yaml](../../../base/ca/openshift/pki-ca-is.yaml)
- [/usr/share/pki/ca/openshift/pki-ca-deployment.yaml](../../../base/ca/openshift/pki-ca-deployment.yaml)
- [/usr/share/pki/ca/openshift/pki-ca-svc.yaml](../../../base/ca/openshift/pki-ca-svc.yaml)
- [/usr/share/pki/ca/openshift/pki-ca-route.yaml](../../../base/ca/openshift/pki-ca-route.yaml)

Customize the configuration as needed. Deploy the responder with the following command:

```
$ oc apply -f/usr/share/pki/ca/openshift/pki-ca-{certs,database,realm,is,deployment,svc,route}.yaml
```

Once it's deployed, get the route's hostname with the following command:

```
$ oc get routes pki-ca
```

The responder should be accessible at http://&lt;hostname&gt;/ca.

## Deploying Permanent CA Signing Certificate

To deploy a permanent CA signing certificate, the certificate and key need to be deployed in a secret.
A sample configuration for the secret is available at
[/usr/share/pki/ca/openshift/pki-ca-certs.yaml](../../../base/ca/openshift/pki-ca-certs.yaml).

Customize the configuration as needed. Deploy the secret with the following command:

```
$ oc apply -f /usr/share/pki/ca/openshift/pki-ca-certs.yaml
```

Alternatively, the secret can be created from files directly.
Prepare a folder to store the files (e.g. certs).

If the CA signing certificate and key are available in PEM format,
store the certificate in a file called **ca_signing.crt**,
and store the key in a file called **ca_signing.key**.

If the CA signing certificate is stored in an NSS database,
export the certificate and the key and then import them into a PKCS #12 file called **certs.p12**
with a **ca_signing** friendly name,
and store the PKCS #12 password in a file called **password**.

For example:

```
$ echo <PKCS #12 password> > password
$ pki -d <NSS database directory> -c <NSS database password> pkcs12-cert-import \
    --pkcs12 certs.p12 \
    --password-file password \
    --friendly-name ca_signing \
    <cert nickname in NSS database>
```

Deploy the secret with the following commands:

```
$ oc delete secret pki-ca-certs
$ oc create secret generic pki-ca-certs --from-file=certs --save-config=true
```

Once it's deployed, restart the responder by deleting the current pods with the following command:

```
$ oc delete pods -l app=pki-ca
```

## Deploying Permanent Database

To deploy a permanent database, use OpenShift console or **oc new-app** command.
For example, deploy a PostgreSQL database with the following command:

```
$ oc new-app postgresql-persistent \
    -p POSTGRESQL_USER=admin \
    -p POSTGRESQL_PASSWORD=Secret.123 \
    -p POSTGRESQL_DATABASE=pki-ca
```

Next, configure the PKI CA to use the permanent database.
A sample database configuration for PKI CA is available at
[/usr/share/pki/ca/openshift/pki-ca-database.yaml](../../../base/ca/openshift/pki-ca-database.yaml).

Customize the configuration as needed. Deploy the configuration with the following command:

```
$ oc apply -f /usr/share/pki/ca/openshift/pki-ca-database.yaml
```

Restart the responder by deleting the current pods with the following command:

```
$ oc delete pods -l app=pki-ca
```

To verify the database connection, list the responder's pods with the following command:

```
$ oc get pods -l app=pki-ca
```

Select one of the pods, then execute the following command:

```
$ oc rsh <pod name> \
    psql postgres://admin:Secret.123@postgresql/pki-ca
```

## Deploying Permanent Realm

A sample realm configuration for PKI ACME responder is available at
[/usr/share/pki/ca/openshift/pki-ca-realm.yaml](../../../base/ca/openshift/pki-ca-realm.yaml).

Customize the configuration as needed. Deploy the configuration with the following command:

```
$ oc apply -f /usr/share/pki/ca/openshift/pki-ca-realm.yaml
```

Restart the responder by deleting the current pods with the following command:

```
$ oc delete pods -l app=pki-ca
```

## Deploying Secure Route

To deploy a secure route, prepare a route configuration that contains the following properties:

- **certificate**: The external SSL server certificate
- **key**: The external SSL server key
- **caCertificate**: The CA certificate that issued the external SSL server certificate
- **destinationCACertificate**: The CA signing certificate deployed in **pki-ca-certs** secret

A sample route configuration is available at
[/usr/share/pki/ca/openshift/pki-ca-route.yaml](../../../base/ca/openshift/pki-ca-route.yaml).

Customize the configuration as needed. Deploy the configuration with the following commands:

```
$ oc delete route pki-ca
$ oc apply -f /usr/share/pki/ca/openshift/pki-ca-route.yaml
```

The responder should now be accessible at https://&lt;hostname&gt;/ca.
