//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.cli;

import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.account.AccountClient;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;

/**
 * This class represents a CLI command that will access a PKI subsystem.
 *
 * @author Endi S. Dewata
 */
public class SubsystemCommandCLI extends CommandCLI {

    public SubsystemCLI subsystemCLI;

    public SubsystemCommandCLI(String name, String description, CLI parent) {
        super(name, description, parent);

        // find subsystem CLI object in CLI hierarchy
        CLI cli = parent;
        while (cli != null) {
            if (cli instanceof SubsystemCLI subsystemCLI) {
                // found subsystem CLI object
                this.subsystemCLI = subsystemCLI;
                break;
            } else {
                // keep looking
                cli = cli.parent;
            }
        }
    }

    public void createOptions() {

        super.createOptions();

        Option option = new Option("U", true, "Server URL");
        option.setArgName("uri");
        options.addOption(option);

        option = new Option("n", true, "Nickname for client certificate authentication");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option("u", true, "Username for basic authentication");
        option.setArgName("username");
        options.addOption(option);

        option = new Option("w", true, "Password for basic authentication");
        option.setArgName("password");
        options.addOption(option);

        option = new Option("W", true, "Password file for basic authentication");
        option.setArgName("passwordfile");
        options.addOption(option);

        option = new Option(null, "skip-revocation-check", false, "Do not perform revocation check");
        options.addOption(option);

        option = new Option(null, "reject-cert-status", true, "Comma-separated list of rejected certificate validity statuses");
        option.setArgName("list");
        options.addOption(option);

        option = new Option(null, "ignore-cert-status", true, "Comma-separated list of ignored certificate validity statuses");
        option.setArgName("list");
        options.addOption(option);

        option = new Option(null, "ignore-banner", false, "Ignore access banner");
        options.addOption(option);
    }

    @Override
    public void execute(String[] args) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = null;
        SubsystemClient subsystemClient = null;
        AccountClient accountClient = null;

        // login if username or nickname is specified
        ClientConfig config = getConfig();
        if (config.getUsername() != null || config.getCertNickname() != null) {

            // connect to the server
            client = mainCLI.getClient();

            // connect to the subsystem
            subsystemClient = subsystemCLI.getSubsystemClient(client);

            // authenticate against the subsystem
            accountClient = new AccountClient(subsystemClient);
            accountClient.login();
        }

        // execute the actual command
        super.execute(args);

        // logout if there is no failures
        if (config.getUsername() != null || config.getCertNickname() != null) {
            accountClient.logout();
        }
    }
}
