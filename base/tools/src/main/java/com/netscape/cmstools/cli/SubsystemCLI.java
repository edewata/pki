// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.cli;

import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKICertificateApprovalCallback;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;


/**
 * @author Endi S. Dewata
 */
public class SubsystemCLI extends CLI {

    public MainCLI mainCLI;

    public SubsystemCLI(String name, String description, MainCLI mainCLI) {
        super(name, description, mainCLI);

        this.mainCLI = mainCLI;
    }

    @Override
    public String getFullName() {
        // do not include parent's name
        return name;
    }

    public PKIClient getPKIClient(CommandLine cmd) throws Exception {

        String serverURL = cmd.getOptionValue("U");
        if (serverURL == null) {
            // use shared PKIClient
            return mainCLI.getClient();
        }

        // create new PKIClient

        ClientConfig config = new ClientConfig(mainCLI.config);
        config.setServerURL(serverURL);

        String certNickname = cmd.getOptionValue("n");
        config.setCertNickname(certNickname);

        String username = cmd.getOptionValue("u");
        config.setUsername(username);

        String password = cmd.getOptionValue("w");
        if (password == null) {
            String passwordFile = cmd.getOptionValue("W");
            if (passwordFile != null) {
                password = mainCLI.loadPassword(passwordFile);
            }
        }
        config.setPassword(password);

        boolean skipRevocationCheck = cmd.hasOption("skip-revocation-check");
        config.setCertRevocationVerify(!skipRevocationCheck);

        String list = cmd.getOptionValue("reject-cert-status");
        Collection<Integer> rejectedCertStatuses = new ArrayList<>();
        mainCLI.convertCertStatusList(list, rejectedCertStatuses);

        list = cmd.getOptionValue("ignore-cert-status");
        Collection<Integer> ignoredCertStatuses = new ArrayList<>();
        mainCLI.convertCertStatusList(list, ignoredCertStatuses);

        PKICertificateApprovalCallback callback = new PKICertificateApprovalCallback();
        callback.reject(rejectedCertStatuses);
        callback.ignore(ignoredCertStatuses);

        boolean ignoreBanner = cmd.hasOption("ignore-banner");

        return mainCLI.createClient(config, callback, ignoreBanner);
    }

    public SubsystemClient getSubsystemClient(PKIClient client) throws Exception {
        return null;
    }
}
