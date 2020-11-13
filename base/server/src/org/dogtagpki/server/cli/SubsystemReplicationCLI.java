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
public class SubsystemReplicationCLI extends CLI {

    public SubsystemReplicationCLI(CLI parent) {
        super("replication", parent.parent.name.toUpperCase() + " replication management commands", parent);

        addModule(new SubsystemReplicationAddCLI(this));
    }
}
