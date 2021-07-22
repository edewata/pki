#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# https://docs.fedoraproject.org/en-US/containers/guidelines/guidelines/
#
# This file is used to create an ACME image automatically in Quay.io.
# The build is done in a single stage since Quay.io does not support
# multi-stage build.

FROM registry.fedoraproject.org/fedora-minimal:latest

ARG NAME="pki-acme"
ARG SUMMARY="Dogtag PKI ACME Responder"
ARG LICENSE="GPLv2 and LGPLv2"
ARG VERSION="0"
ARG ARCH="x86_64"
ARG MAINTAINER="Dogtag PKI Team <devel@lists.dogtagpki.org>"
ARG VENDOR="Dogtag"
ARG COMPONENT="pki-core"
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
RUN if [ -n "$COPR_REPO" ]; then \
    cd /etc/yum.repos.d; \
    curl -O https://copr.fedorainfracloud.org/coprs/g/pki/master/repo/fedora-34/group_pki-master-fedora-34.repo; \
    fi

# Import PKI sources
COPY . /tmp/pki/
WORKDIR /tmp/pki

# Install build and runtime dependencies
RUN microdnf install -y systemd git rpm-build tzdata bind-utils iputils abrt-java-connector postgresql postgresql-jdbc
RUN tools/bin/microdnf-builddep.sh
RUN microdnf install -y \
nss \
apache-commons-cli \
apache-commons-codec \
apache-commons-io \
apache-commons-lang3 \
apache-commons-logging \
apache-commons-net \
glassfish-jaxb-api \
java-11-openjdk-headless \
jaxb-impl \
jpackage-utils \
jss \
ldapjdk \
resteasy-client \
resteasy-core \
resteasy-jackson2-provider \
resteasy-jaxb-provider \
slf4j \
slf4j-jdk14 \
xalan-j2 \
xerces-j2 \
xml-commons-resolver \
freeipa-healthcheck-core \
hostname \
keyutils \
openldap-clients \
openssl \
policycoreutils \
policycoreutils-python-utils \
procps-ng \
python3-libselinux \
python3-lxml \
python3-policycoreutils \
selinux-policy-targeted \
tomcat \
tomcatjss \
java-11-openjdk-headless \
jpackage-utils \
jss \
nss \
python3-flake8 \
python3-pylint \
nss-tools \
nss-tools \
openldap-clients \
openssl \
python3-cryptography \
python3-ldap \
python3-lxml \
python3-requests \
python3-six

# Build PKI packages
RUN ./build.sh --with-pkgs=base,server,acme --work-dir=/tmp/build rpm

# Install PKI packages
RUN cd /tmp/build/RPMS; ls -la; rpm -ivh *.rpm

# Install PostgreSQL JDBC driver
RUN ln -s /usr/share/java/postgresql-jdbc/postgresql.jar /usr/share/pki/server/common/lib/postgresql.jar

# Create PKI server
RUN pki-server create tomcat@pki --user tomcat --group root

# Create NSS database
RUN pki-server nss-create -i tomcat@pki --no-password

# Enable JSS
RUN pki-server jss-enable -i tomcat@pki

# Configure SSL connector
RUN pki-server http-connector-add -i tomcat@pki \
  --port 8443 \
  --scheme https \
  --secure true \
  --sslEnabled true \
  --sslProtocol SSL \
  --sslImpl org.dogtagpki.tomcat.JSSImplementation \
  Secure

# Configure SSL server certificate
RUN pki-server http-connector-cert-add -i tomcat@pki \
  --keyAlias sslserver \
  --keystoreType pkcs11 \
  --keystoreProvider Mozilla-JSS

# Create PKI ACME application
RUN pki-server acme-create -i tomcat@pki

# Use in-memory database by default
RUN cp /usr/share/pki/acme/database/in-memory/database.conf /var/lib/tomcats/pki/conf/acme

# Use NSS issuer by default
RUN cp /usr/share/pki/acme/issuer/nss/issuer.conf /var/lib/tomcats/pki/conf/acme

# Use in-memory realm by default
RUN cp /usr/share/pki/acme/realm/in-memory/realm.conf /var/lib/tomcats/pki/conf/acme

# Remove PKI ACME web application logging.properties so the logs will appear on the console
RUN rm -f /usr/share/pki/acme/webapps/acme/WEB-INF/classes/logging.properties

# Deploy PKI ACME application
RUN pki-server acme-deploy -i tomcat@pki

# Grant the root group the full access to PKI ACME files
# https://www.openshift.com/blog/jupyter-on-openshift-part-6-running-as-an-assigned-user-id
RUN chgrp -Rf root /var/lib/tomcats/pki
RUN chmod -Rf g+rw /var/lib/tomcats/pki

VOLUME [ \
    "/var/lib/tomcats/pki/conf/certs", \
    "/var/lib/tomcats/pki/conf/acme/metadata", \
    "/var/lib/tomcats/pki/conf/acme/database", \
    "/var/lib/tomcats/pki/conf/acme/issuer", \
    "/var/lib/tomcats/pki/conf/acme/realm" ]

CMD [ "/usr/share/pki/acme/bin/pki-acme-run" ]
