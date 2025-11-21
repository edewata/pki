//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.cli;

import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.account.AccountClient;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKICertificateApprovalCallback;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;

/**
 * This class represents a CLI command that will access a PKI subsystem.
 *
 * @author Endi S. Dewata
 */
public class SubsystemCommandCLI extends CommandCLI {

    public SubsystemCLI subsystemCLI;

    public String serverURL;
    public String certNickname;
    public String username;
    public String password;
    public String passwordFile;

    public boolean skipRevocationCheck;
    public Collection<Integer> rejectedCertStatuses = new ArrayList<>();
    public Collection<Integer> ignoredCertStatuses = new ArrayList<>();

    public boolean ignoreBanner;

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

    @Override
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
    public CommandLine parseOptions(String[] args) throws Exception {

        CommandLine cmd = super.parseOptions(args);

        serverURL = cmd.getOptionValue("U");
        certNickname = cmd.getOptionValue("n");
        username = cmd.getOptionValue("u");
        password = cmd.getOptionValue("w");
        passwordFile = cmd.getOptionValue("W");

        skipRevocationCheck = cmd.hasOption("skip-revocation-check");

        String list = cmd.getOptionValue("reject-cert-status");
        MainCLI.convertCertStatusList(list, rejectedCertStatuses);

        list = cmd.getOptionValue("ignore-cert-status");
        MainCLI.convertCertStatusList(list, ignoredCertStatuses);

        ignoreBanner = cmd.hasOption("ignore-banner");

        return cmd;
    }

    public PKIClient getPKIClient() throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();

        if (serverURL == null) {
            // use shared PKIClient
            return mainCLI.getPKIClient();
        }

        // create new PKIClient for this command

        ClientConfig config = new ClientConfig(mainCLI.config);
        config.setServerURL(serverURL);
        config.setCertNickname(certNickname);
        config.setUsername(username);

        if (password == null) {
            if (passwordFile != null) {
                password = mainCLI.loadPassword(passwordFile);
            }
        }
        config.setPassword(password);

        config.setCertRevocationVerify(!skipRevocationCheck);

        PKICertificateApprovalCallback callback = new PKICertificateApprovalCallback();
        callback.reject(rejectedCertStatuses);
        callback.ignore(ignoredCertStatuses);

        return mainCLI.createPKIClient(config, callback, ignoreBanner);
    }

    public SubsystemClient getSubsystemClient(PKIClient client) throws Exception {
        return subsystemCLI.getSubsystemClient(client);
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
            client = getPKIClient();

            // connect to the subsystem
            subsystemClient = getSubsystemClient(client);

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
