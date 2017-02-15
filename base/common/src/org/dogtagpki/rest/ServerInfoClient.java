//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2017 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---

package org.dogtagpki.rest;

import java.net.URISyntaxException;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class ServerInfoClient extends Client {

    public ServerInfoResource resource;

    public ServerInfoClient(PKIClient client) throws URISyntaxException {
        super(client, "pki", "server-info");
        init();
    }

    public void init() throws URISyntaxException {
        resource = createProxy(ServerInfoResource.class);
    }

    public ServerInfo getServerInfo() throws Exception {

        Response response = resource.getServerInfo();
        ServerInfo serverInfo = client.getEntity(response, ServerInfo.class);

        return serverInfo;
    }
}
