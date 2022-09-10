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
COPY . /usr/local/src/pki/
WORKDIR /usr/local/src/pki

# Install build dependencies
RUN dnf builddep -y --spec pki.spec

# Install remaining runtime dependencies
RUN dnf install -y \
    hostname \
    policycoreutils-python-utils \
    selinux-policy-targeted \
    openldap-clients \
    python3-policycoreutils \
    jpackage-utils

# Build PKI binaries
RUN ./build.sh \
    --work-dir=build \
    --java-home=/usr/lib/jvm/java-17-openjdk \
    --python-dir=/usr/lib/python3.10/site-packages \
    dist

# Install PKI binaries
RUN ./build.sh \
    --work-dir=build \
    --java-home=/usr/lib/jvm/java-17-openjdk \
    --python-dir=/usr/lib/python3.10/site-packages \
    install

# Grant the root group the full access to PKI CA files
# https://www.openshift.com/blog/jupyter-on-openshift-part-6-running-as-an-assigned-user-id
RUN chgrp -Rf root /usr/local/src/pki
RUN chmod -Rf g+rw /usr/local/src/pki

RUN chgrp -Rf root /etc/pki
RUN chmod -Rf g+rw /etc/pki

RUN chgrp -Rf root /var/lib/pki
RUN chmod -Rf g+rw /var/lib/pki

RUN chgrp -Rf root /var/log/pki
RUN chmod -Rf g+rw /var/log/pki

RUN chgrp -Rf root /etc/sysconfig
RUN chmod -Rf g+rw /etc/sysconfig

RUN chgrp -Rf root /etc/sysconfig/pki/tomcat
RUN chmod -Rf g+rw /etc/sysconfig/pki/tomcat

RUN pki -d /etc/pki/pki-tomcat/alias nss-create --force
RUN chgrp -Rf root /etc/pki/pki-tomcat
RUN chmod -Rf g+rw /etc/pki/pki-tomcat

RUN mkdir -p /.dogtag
RUN chgrp -Rf root /.dogtag
RUN chmod -Rf g+rw /.dogtag

RUN mkdir -p /certs
RUN chgrp -Rf root /certs
RUN chmod -Rf g+rw /certs

RUN mkdir -p /database
RUN chgrp -Rf root /database
RUN chmod -Rf g+rw /database

VOLUME [ "/certs", "/database" ]

CMD [ "/usr/share/pki/ca/bin/pki-ca-run" ]
