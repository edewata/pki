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

package org.dogtagpki.server.rest;

import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.dogtagpki.rest.ServerInfo;
import org.dogtagpki.rest.ServerInfoResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class ServerInfoService extends PKIService implements ServerInfoResource {

    private static Logger logger = LoggerFactory.getLogger(ServerInfoService.class);

    @Override
    public Response getServerInfo() throws Exception {

        HttpSession session = servletRequest.getSession();
        logger.debug("Session " + session.getId() + ": getting server info");

        ServerInfo serverInfo = new ServerInfo();
        serverInfo.setName("PKI Server");
        serverInfo.setVersion(System.getenv("PKI_VERSION"));

        boolean warningEnabled = isWarningEnabled();

        if (warningEnabled) {
            String message = getWarningMessage();
            serverInfo.setWarning(message);
        }

        ResponseBuilder builder = createOKResponseBuilder(serverInfo);
/*
        if (warningEnabled) {
            builder.cookie(NewCookie.valueOf(PKI_WARNING + "=received; Path=/"));
        }
*/
        return builder.build();
    }
}
