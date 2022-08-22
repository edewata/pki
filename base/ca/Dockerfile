#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# https://docs.fedoraproject.org/en-US/containers/guidelines/guidelines/

FROM registry.fedoraproject.org/fedora:latest

ARG NAME="pki-ca"
ARG SUMMARY="Dogtag PKI Certificate Authority"
ARG LICENSE="GPLv2 and LGPLv2"
ARG VERSION="0"
ARG ARCH="x86_64"
ARG MAINTAINER="Dogtag PKI Team <devel@lists.dogtagpki.org>"
ARG VENDOR="Dogtag"
ARG COMPONENT="dogtag-pki"
ARG COPR_REPO="@pki/master"

LABEL name="$NAME" \
      summary="$SUMMARY" \
      license="$LICENSE" \
      version="$VERSION" \
      architecture="$ARCH" \
      maintainer="$MAINTAINER" \
      vendor="$VENDOR" \
      usage="podman run -p 8080:8080 -p 8443:8443 $NAME" \
      com.redhat.component="$COMPONENT"

EXPOSE 8080 8443

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf install -y dnf-plugins-core; dnf copr enable -y $COPR_REPO; fi

# Import PKI sources
COPY . /tmp/pki/
WORKDIR /tmp/pki

# Install PKI dependencies
RUN dnf builddep -y --spec pki.spec
RUN dnf install -y \
    hostname \
    policycoreutils \
    policycoreutils-python-utils \
    selinux-policy-targeted \
    nss \
    nss-tools \
    p11-kit-trust \
    openssl \
    openldap-clients \
    python3 \
    python3-cryptography \
    python3-ldap \
    python3-libselinux \
    python3-lxml \
    python3-policycoreutils \
    python3-requests \
    java-17-openjdk-headless \
    jpackage-utils \
    slf4j \
    slf4j-jdk14 \
    apache-commons-cli \
    apache-commons-codec \
    apache-commons-io \
    apache-commons-lang3 \
    apache-commons-logging \
    apache-commons-net \
    resteasy-core \
    resteasy-jackson2-provider \
    resteasy-client \
    freeipa-healthcheck-core \
    tomcat \
    jss \
    tomcatjss \
    ldapjdk

# Build and install PKI binaries
RUN ./build.sh \
    --work-dir=/tmp/build \
    --python-dir=/usr/lib/python3.10/site-packages \
    --java-home=/usr/lib/jvm/java-17-openjdk \
    dist
RUN ./build.sh \
    --work-dir=/tmp/build \
    --python-dir=/usr/lib/python3.10/site-packages \
    --java-home=/usr/lib/jvm/java-17-openjdk \
    install

# Create PKI server
RUN pki-server create --user tomcat --group root

# Create NSS database
RUN pki-server nss-create --no-password

VOLUME [ "/certs" ]

CMD [ "/usr/share/pki/ca/bin/pki-ca-run" ]
