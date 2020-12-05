//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import org.dogtagpki.cli.CLI;

/**
 * @author Endi S. Dewata
 */
public class SubsystemDBACLCLI extends CLI {

    public SubsystemDBACLCLI(CLI parent) {
        super("acl", parent.parent.name.toUpperCase() + " database ACL management commands", parent);

        addModule(new SubsystemDBACLAddCLI(this));
        addModule(new SubsystemDBACLDeleteCLI(this));
    }
}
