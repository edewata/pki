# pki-server-upgrade 8 "Jul 22, 2013" PKI "PKI Server Upgrade Tool"

## NAME

pki-server-upgrade - Tool for upgrading PKI server configuration.

## SYNOPSIS

**pki-server** [*CLI-options*] **upgrade** [*OPTIONS*]

## DESCRIPTION

There are two parts to upgrading PKI server:
upgrading the system configuration files used by both the client and the server processes
and upgrading the server configuration files.

When upgrading PKI server, the existing server configuration files (e.g. **server.xml**, **web.xml**)
may need to be upgraded because the content may have changed from one version to another.
The configuration upgrade is executed automatically during RPM upgrade.
However, in case there is a problem, the process can also be run manually using **pki-server upgrade**.

The server upgrade process is done incrementally using upgrade scriptlets.
A server consists of the server instance itself and the subsystems running in that instance.
The upgrade process executes one scriptlet at a time,
running through each component (server instance and subsystem) in parallel and completing before executing the next scriptlet.
If one component encounters an error, that component is skipped in the subsequent upgrade scriptlets.
The upgrade process and scriptlet execution for each component is monitored in upgrade trackers.
A counter shows the latest index number for the most recently executed scriptlet;
when all scriptlets have run, the component tracker shows the updated version number.

The scriptlets are stored in the upgrade directory:

```
/usr/share/pki/server/upgrade/<version>/<index>-<name>
```

The **version** is the server version to be upgraded. The **index** is the script execution order.
The **name** is the scriptlet name.

During upgrade, the scriptlets will back up all changes to the file system into the following folder:

```
/var/log/pki/server/upgrade/<version>/<index>
```

The **version** and **index** values indicate the scriptlet being executed.
A copy of the files and folders that are being modified or removed will be stored in **oldfiles**.
The names of the newly-added files and folders will be stored in **newfiles**.

The instance upgrade process is tracked using this file:

```
/var/lib/pki/<instance>/conf/tomcat.conf
```

The subsystem upgrade process is tracked using this file:

```
/var/lib/pki/<instance>/<subsystem>/conf/CS.cfg
```

The file stores the current configuration version and the last successful scriptlet index.

## OPTIONS

### General options

**--status**  
    Show upgrade status only **without** performing the upgrade.

**--revert**  
    Revert the last version.

**-i**, **--instance** *instance*  
    Upgrade a specific instance only.

**-X**  
    Show advanced options.

**-v**, **--verbose**  
    Run in verbose mode.

**-h**, **--help**  
    Show this help message.

### Advanced options

The advanced options circumvent the normal upgrade process by changing the tracker information.

**WARNING:** These options may render the system unusable.

**--remove-tracker**  
    Remove the tracker.

**--reset-tracker**  
    Reset the tracker to match the package version.

**--set-tracker** *version*  
    Set the tracker to a specific version.

## OPERATIONS

### Upgrade process

To start the upgrade process:

```
$ pki-server upgrade
```

### Upgrade status

To check the upgrade status:

```
$ pki-server upgrade --status
```

### Troubleshooting

Check the scriptlet to see which operations are being executed.
Once the error is identified and corrected, the upgrade can be resumed by re-running **pki-server upgrade**.

If necessary, the upgrade can be run in verbose mode:

```
$ pki-server upgrade --verbose
```

It is possible to rerun a failed upgrade for a specific instance:

```
$ pki-server upgrade --instance pki-tomcat
```

### Reverting an upgrade

If necessary, the upgrade can be reverted:

```
$ pki-server upgrade --revert
```

Files and folders that were created by the scriptlet will be removed.
Files and folders that were modified or removed by the scriptlet will be restored.

## AUTHORS

Ade Lee &lt;alee@redhat.com&gt;, Ella Deon Lackey &lt;dlackey@redhat.com&gt;, and Endi S. Dewata &lt;edewata@redhat.com&gt;.

## COPYRIGHT

Copyright (c) 2013 Red Hat, Inc.
This is licensed under the GNU General Public License, version 2 (GPLv2).
A copy of this license is available at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
