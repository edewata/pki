#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# https://docs.fedoraproject.org/en-US/containers/guidelines/guidelines/

FROM registry.fedoraproject.org/fedora:31

ARG NAME="pki-ca"
ARG SUMMARY="Dogtag PKI Certificate Authority"
ARG LICENSE="GPLv2 and LGPLv2"
ARG VERSION="0"
ARG ARCH="x86_64"
ARG MAINTAINER="Dogtag PKI Team <pki-devel@redhat.com>"
ARG VENDOR="Dogtag"
ARG COMPONENT="pki-core"
ARG COPR_REPO=""

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

# Install packages
RUN dnf install -y bind-utils iputils abrt-java-connector postgresql postgresql-jdbc pki-ca

# Install PostgreSQL JDBC driver
RUN ln -s /usr/share/java/postgresql-jdbc/postgresql.jar /usr/share/pki/server/common/lib/postgresql.jar

# Install development packages (if available)
COPY RPMS /tmp/RPMS/
RUN dnf localinstall -y /tmp/RPMS/* && rm -rf /tmp/RPMS

# Install README.md
RUN cp /usr/share/pki/ca/README.md .

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

# Create PKI CA application
RUN pki-server ca-create -i tomcat@pki

RUN pki-server ca-config-set -i tomcat@pki internaldb.ldapconn.host openldap-2441-centos7
RUN pki-server ca-config-set -i tomcat@pki internaldb.ldapconn.port 389
RUN pki-server ca-config-set -i tomcat@pki internaldb.ldapauth.authtype BasicAuth
RUN pki-server ca-config-set -i tomcat@pki internaldb.ldapauth.bindDN "cn=Manager,dc=example,dc=com"
RUN pki-server ca-config-set -i tomcat@pki internaldb.ldapauth.bindPassword Secret.123
RUN pki-server ca-config-set -i tomcat@pki internaldb.database ca
RUN pki-server ca-config-set -i tomcat@pki internaldb.basedn "dc=ca,dc=pki,dc=example,dc=com"

RUN pki-server ca-config-set -i tomcat@pki ca.crl.MasterCRL.enable false

RUN pki-server ca-config-unset -i tomcat@pki auths.impl.FlatFileAuth.class
RUN pki-server ca-config-unset -i tomcat@pki auths.instance.flatFileAuth.pluginName
RUN pki-server ca-config-unset -i tomcat@pki auths.instance.flatFileAuth.fileName

# Use in-memory realm by default
RUN cp /usr/share/pki/ca/realm/in-memory/realm.conf /var/lib/tomcats/pki/conf/ca

# Remove PKI CA web application logging.properties so the logs will appear on the console
RUN rm -f /usr/share/pki/ca/webapps/ca/WEB-INF/classes/logging.properties

# Deploy PKI CA application
RUN pki-server ca-deploy -i tomcat@pki

# Grant the root group the full access to PKI CA files
# https://www.openshift.com/blog/jupyter-on-openshift-part-6-running-as-an-assigned-user-id
RUN chgrp -Rf root /var/lib/tomcats/pki && chmod -Rf g+rw /var/lib/tomcats/pki

VOLUME [ \
    "/var/lib/tomcats/pki/conf/certs", \
    "/var/lib/tomcats/pki/conf/ca/database", \
    "/var/lib/tomcats/pki/conf/ca/realm" ]

CMD [ "/usr/share/pki/ca/bin/pki-ca-run" ]
