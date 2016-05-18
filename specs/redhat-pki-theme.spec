Name:             redhat-pki-theme
Version:          10.3.1
Release:          1%{?dist}
Summary:          Certificate System - Red Hat PKI Theme Components
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Base

BuildArch:        noarch

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake
BuildRequires:    java-devel >= 1:1.7.0
BuildRequires:    jpackage-utils >= 1.7.5-10

%if 0%{?rhel}
# NOTE:  In the future, as a part of its path, this URL will contain a release
#        directory which consists of the fixed number of the upstream release
#        upon which this tarball was originally based.
Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{version}/%{release}/rhel/%{name}-%{version}%{?prerel}.tar.gz
%else
Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{version}/%{release}/%{name}-%{version}%{?prerel}.tar.gz
%endif

%global overview                                                       \
Several PKI packages utilize a "virtual" theme component.  These       \
"virtual" theme components are "Provided" by various theme "flavors"   \
including "redhat" or a user customized theme package.  Consequently,  \
all "redhat" and any customized theme components MUST be mutually      \
exclusive!                                                             \
%{nil}

%description %{overview}


%package -n       redhat-pki-server-theme
Summary:          Certificate System - PKI Server Framework User Interface
Group:            System Environment/Base

Obsoletes:        redhat-pki-common-theme <= %{version}-%{release}
Obsoletes:        redhat-pki-common-ui
Obsoletes:        redhat-pki-ca-theme <= %{version}-%{release}
Obsoletes:        redhat-pki-ca-ui
Obsoletes:        redhat-pki-kra-theme <= %{version}-%{release}
Obsoletes:        redhat-pki-kra-ui
Obsoletes:        redhat-pki-ocsp-theme <= %{version}-%{release}
Obsoletes:        redhat-pki-ocsp-ui
Obsoletes:        redhat-pki-tks-theme <= %{version}-%{release}
Obsoletes:        redhat-pki-tks-ui
Obsoletes:        redhat-pki-ra-theme <= %{version}-%{release}
Obsoletes:        redhat-pki-ra-ui
Obsoletes:        redhat-pki-tps-theme <= %{version}-%{release}
Obsoletes:        redhat-pki-tps-ui

Provides:         redhat-pki-common-theme = %{version}-%{release}
Provides:         pki-server-theme = %{version}-%{release}
Provides:         pki-common-theme = %{version}-%{release}
Provides:         pki-common-ui = %{version}-%{release}

Provides:         redhat-pki-ca-theme = %{version}-%{release}
Provides:         pki-ca-theme = %{version}-%{release}
Provides:         pki-ca-ui = %{version}-%{release}

Provides:         redhat-pki-kra-theme = %{version}-%{release}
Provides:         pki-kra-theme = %{version}-%{release}
Provides:         pki-kra-ui = %{version}-%{release}

Provides:         redhat-pki-ocsp-theme = %{version}-%{release}
Provides:         pki-ocsp-theme = %{version}-%{release}
Provides:         pki-ocsp-ui = %{version}-%{release}

Provides:         redhat-pki-tks-theme = %{version}-%{release}
Provides:         pki-tks-theme = %{version}-%{release}
Provides:         pki-tks-ui = %{version}-%{release}

Provides:         redhat-pki-tps-theme = %{version}-%{release}
Provides:         pki-tps-theme = %{version}-%{release}
Provides:         pki-tps-ui = %{version}-%{release}

%description -n   redhat-pki-server-theme
This PKI Server Framework User Interface contains
the Red Hat textual and graphical user interface for the PKI Server Framework.

This package is used by the Red Hat Certificate System.

%{overview}


%package -n       redhat-pki-console-theme
Summary:          Certificate System - PKI Console User Interface
Group:            System Environment/Base

Requires:         java >= 1:1.7.0

%if 0%{?rhel}
# EPEL version of Red Hat "theme" conflicts with all versions of Dogtag "theme"
Conflicts:        dogtag-pki-console-theme
Conflicts:        dogtag-pki-console-ui
%endif

Obsoletes:        redhat-pki-console-ui <= 9

Provides:         pki-console-theme = %{version}-%{release}
Provides:         pki-console-ui = %{version}-%{release}

%description -n   redhat-pki-console-theme
This PKI Console User Interface contains
the Red Hat textual and graphical user interface for the PKI Console.

This package is used by the Red Hat Certificate System.

%{overview}


%prep


%setup -q -n %{name}-%{version}%{?prerel}


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DVERSION=%{version}-%{release} \
	-DVAR_INSTALL_DIR:PATH=/var \
	-DBUILD_REDHAT_PKI_THEME:BOOL=ON \
	-DJAVA_LIB_INSTALL_DIR=%{_jnidir} \
	..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"


# NOTE:  Several "theme" packages require ownership of the "/usr/share/pki"
#        directory because the PKI subsystems (CA, KRA, OCSP, TKS, TPS)
#        which require them may be installed either independently or in
#        multiple combinations.

%files -n redhat-pki-server-theme
%defattr(-,root,root,-)
%doc redhat/common-ui/LICENSE
%dir %{_datadir}/pki
%{_datadir}/pki/common-ui/


%files -n redhat-pki-console-theme
%defattr(-,root,root,-)
%doc redhat/console-ui/LICENSE
%{_javadir}/pki/


%changelog
* Tue May 17 2016 Dogtag Team <pki-devel@redhat.com> 10.3.1-1
- Update version number to 10.3.1

* Sat Jul 18 2015 Dogtag Team <pki-devel@redhat.com> 10.2.6-1
- Update version number to 10.2.6

* Sat Jun 20 2015 Dogtag Team <pki-devel@redhat.com> 10.2.5-2
- Remove ExcludeArch directive

* Fri Jun 19 2015 Dogtag Team <pki-devel@redhat.com> 10.2.5-1
- Update version number to 10.2.5

* Tue May 26 2015 Dogtag Team <pki-devel@redhat.com> 10.2.4-1
- Updated version number to 10.2.4

* Fri Apr 24 2015 Dogtag Team <pki-devel@redhat.com> 10.2.3-1
- Initial release
