Building PKI CA Image
=====================

## Overview

This document describes the process to build the container image for PKI Certificate Authority.

## Building PKI CA Image

Build PKI CA container image with the following command:

```
$ ./build.sh image
```

## Publishing PKI CA Image

Tag the image with the following command:

```
$ podman tag pki-ca:latest quay.io/dogtagpki/pki-ca:latest
```

Push the image to the repository with the following command:

```
$ podman push quay.io/dogtagpki/pki-ca:latest
```

## See also

* [Building PKI](../Building_PKI.md)
