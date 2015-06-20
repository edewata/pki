Summary:          Red Hat Public Key Infrastructure (PKI) Suite
Name:             redhat-pki
Version:          10.2.5
Release:          2%{?dist}
# The entire source code is GPLv2 except for 'pki-tps' which is LGPLv2
License:          GPLv2 and LGPLv2
URL:              http://pki.fedoraproject.org/
Group:            System Environment/Daemons
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:        noarch

%define redhat_pki_theme_version   %{version}
%define esc_version                1.1.0
%define jss_version                4.2.6-35
# NOTE:  The following package versions are TLS compliant:
%define pki_core_version           %{version}
%define pki_console_version        %{version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Red Hat PKI theme packages
Requires:         redhat-pki-server-theme >= %{redhat_pki_theme_version}
Requires:         redhat-pki-console-theme >= %{redhat_pki_theme_version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Red Hat PKI core packages
Requires:         pki-ca >= %{pki_core_version}
Requires:         pki-kra >= %{pki_core_version}
Requires:         pki-ocsp >= %{pki_core_version}
Requires:         pki-tks >= %{pki_core_version}
Requires:         pki-tps >= %{pki_core_version}
Requires:         pki-server >= %{pki_core_version}
Requires:         pki-tools >= %{pki_core_version}
Requires:         pki-symkey >= %{pki_core_version}
Requires:         pki-base >= %{pki_core_version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL top-level Red Hat PKI support javadocs
Requires:         jss-javadoc >= %{jss_version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Red Hat PKI core javadocs
Requires:         pki-javadoc >= %{pki_core_version}

# Make certain that this 'meta' package requires the latest version(s)
# of Red Hat PKI console
Requires:         pki-console >= %{pki_console_version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Red Hat PKI clients
Requires:         esc >= %{esc_version}

%description
The Red Hat Public Key Infrastructure (PKI) Suite is comprised of the following
five subsystems and a client (for use by a Token Management System):

  * Certificate Authority (CA)
  * Data Recovery Manager (DRM)
  * Online Certificate Status Protocol (OCSP) Manager
  * Token Key Service (TKS)
  * Token Processing System (TPS)
  * Enterprise Security Client (ESC)

Additionally, it provides a console GUI application used for server and
user/group administration of CA, DRM, OCSP, and TKS, javadocs on portions
of the Red Hat API, as well as various command-line tools used to assist with
a PKI deployment.

To successfully deploy instances of a CA, DRM, OCSP, TKS, or TPS,
a Tomcat Web Server must be up and running locally on this machine.

To meet the database storage requirements of each CA, DRM, OCSP, TKS, or TPS
instance, a 389 Directory Server must be up and running either locally on
this machine, or remotely over the attached network connection.

NOTE:  As a convenience for standalone deployments, this 'redhat-pki'
       top-level meta package supplies Red Hat themes for use by the
       certificate server packages:

         * redhat-pki-theme (Red Hat Certificate System deployments)
           * redhat-pki-server-theme
           * redhat-pki-console-theme

%prep
cat > README <<EOF
This package is just a "meta-package" whose dependencies pull in all of the
packages comprising the Red Hat Public Key Infrastructure (PKI) Suite.
EOF

%install
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc README

%changelog
* Sat Jun 20 2015 Dogtag Team <pki-devel@redhat.com> 10.2.5-2
- Remove ExcludeArch directive

* Fri Jun 19 2015 Dogtag Team <pki-devel@redhat.com> 10.2.5-1
- Update version number to 10.2.5

* Tue May 26 2015 Dogtag Team <pki-devel@redhat.com> 10.2.4-1
- Updated version number to 10.2.4

* Fri Apr 24 2015 Dogtag Team <pki-devel@redhat.com> 10.2.3-1
- Initial release
