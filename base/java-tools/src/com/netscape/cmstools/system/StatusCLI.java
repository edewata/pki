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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.system;

import org.dogtagpki.rest.ServerInfo;
import org.dogtagpki.rest.ServerInfoClient;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class StatusCLI extends CLI {

    public MainCLI mainCLI;

    public StatusCLI(MainCLI mainCLI) {
        super("status", "Show server status", mainCLI);
        this.mainCLI = mainCLI;
    }

    public String getFullName() {
        return name;
    }

    public void printHelp() {
        formatter.printHelp(getFullName(), options);
    }

    public void execute(String[] args) throws Exception {

        PKIClient client = mainCLI.getClient();
        ServerInfoClient serverInfoClient = new ServerInfoClient(client);
        ServerInfo serverInfo = serverInfoClient.getServerInfo();

        System.out.println("  Name: " + serverInfo.getName());
        System.out.println("  Version: " + serverInfo.getVersion());
    }
}
