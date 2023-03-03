//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.system.SecurityDomainHost;

/**
 * @author Endi S. Dewata
 */
public class SDHostCLI extends CLI {

    public SDHostCLI(CLI parent) {
        super("host", "Security domain host management commands", parent);

        addModule(new SDHostAddCLI(this));
        addModule(new SDHostFindCLI(this));
        addModule(new SDHostRemoveCLI(this));
    }

    public static void printSecurityDomainHost(SecurityDomainHost host) {

        System.out.println("  Host ID: " + host.getId());
        System.out.println("  Hostname: " + host.getHostname());
        System.out.println("  Port: " + host.getPort());
        System.out.println("  Secure Port: " + host.getSecurePort());

        if (host.getDomainManager() != null) {
            System.out.println("  Domain Manager: " + host.getDomainManager());
        }

        if (host.getClone() != null) {
            System.out.println("  Clone: " + host.getClone());
        }
    }
}
