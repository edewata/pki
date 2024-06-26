Nuxwdog
=======

## Overview

Nuxwdog is a mechanism that can be used to collect relevant passwords before a server starts.
It utilizes the `keyutils` package and caches the password on Kernel Keyring.

Nuxwdog is used in `Dogtag PKI` to collect passwords before the PKI Server starts. These servers require
passwords to access security databases in order to start, but there was a requirement that no 
unencrypted password files be stored on the system. In this case, nuxwdog is used to prompt the user for the
relevant passwords during server startup. These passwords are then cached, so that systemd can
restart the server without human intervention. This is particularly important for automatically restarting the server
in case of a server crash.

## Operation

### Enabling Nuwxdog

First, shutdown the server with the following command:

```
$ systemctl stop pki-tomcatd@<instance>.service
```

To enable all instances:

```
$ pki-server nuxwdog-enable
```

To enable a specific instance:

```
$ pki-server instance-nuxwdog-enable <instance>
```

If any of the system certificates reside on a cryptographic token other than the
internal NSS database, you will see entries like this in `/var/lib/pki/<instance>/conf/password.conf`:

```
hardware-<token>=<password>
```

In that case, add the following parameter to `/var/lib/pki/<instance>/conf/<subsystem>/CS.cfg`:

```
cms.tokenList=<token>
```

Remove the password file or move it somewhere else:

```
$ mv /var/lib/pki/<instance>/conf/password.conf /path/to/password.conf
```

Restart the server with the following command:

```
$ systemctl start pki-tomcatd-nuxwdog@<instance>.service
[<instance>] Please provide the password for internal: **********
[<instance>] Please provide the password for internaldb: **********
[<instance>] Please provide the password for replicationdb: ***********
```

### Disabling Nuxwdog


First, stop the instance:


```
$ systemctl stop pki-tomcatd-nuxwdog@<instance>.service
```

To disable for all instances:

```
$ pki-server nuxwdog-disable
```

To disable a specific instance:

```
$ pki-server instance-nuxwdog-disable <instance>
```

Finally, restart the instance:

```
$ mv /path/to/password.conf /var/lib/pki/<instance>/conf/password.conf
$ systemctl start pki-tomcatd@<instance>.service
```

## Technical Implementation

### `pki-server-nuxwdog` python script

[`pki-server-nuxwdog`](../../base/server/scripts/pki-server-nuxwdog) script is configured to run before the PKI server
starts using [`systemd` unit file](../../base/server/share/lib/systemd/system/pki-tomcatd-nuxwdog@.service). It uses
`systemd-ask-password` to prompt the user for relevant passwords. The relevant passwords include `internal` and
list of passwords defined in fields `cms.passwordlist` and `cms.tokenList` of every subsystem's `CS.cfg`. The
passwords are stored on the Kernel Keyring provided by the `keyutils` package.

### Kernel Keyring

`Kernel Keyring` offers in-kernel key management and retention facility. Nuxwdog uses this component to cache the
password on the `<pkiuser>'s user keyring`. The keys are cleared off when the PKI server is stopped.

`keyctl` CLI is provided by `keyutils` package to interact with kernel keyring.

### Wrappers available

PKI code base includes support to interact with kernel keyring in different languages. The utility classes available
are listed below:

- **Python:** [pki.keyring.Keyring](../../base/common/python/pki/keyring.py)
- **Java:** [com.netscape.cmsutil.util.Keyring](../../base/common/src/main/java/com/netscape/cmsutil/util/Keyring.java)

**NOTE:** Java doesn't support storing password on keyring, yet. This might be implemented in future releases.

## References

- [Kernel Keyring](http://man7.org/linux/man-pages/man7/keyrings.7.html)
- [keyutils](http://man7.org/linux/man-pages/man1/keyctl.1.html)
- [systemd-devel](https://lists.freedesktop.org/archives/systemd-devel/2018-December/041769.html)
- [systemd.exec](https://www.freedesktop.org/software/systemd/man/systemd.exec.html)
- [systemd.service](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
- [Original Nuxwdog](https://www.dogtagpki.org/wiki/Nuxwdog)
