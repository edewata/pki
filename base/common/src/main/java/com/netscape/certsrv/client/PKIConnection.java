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
// (C) 2015 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.client;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.ws.rs.client.WebTarget;

import org.apache.http.conn.scheme.SchemeLayeredSocketFactory;
import org.apache.http.params.HttpParams;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.ssl.SSLAlertDescription;
import org.mozilla.jss.ssl.SSLAlertEvent;
import org.mozilla.jss.ssl.SSLAlertLevel;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.ssl.SSLSocketListener;

public class PKIConnection implements AutoCloseable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIConnection.class);

    ClientConfig config;

    SSLCertificateApprovalCallback callback;

    int requestCounter;
    int responseCounter;

    File output;

    public PKIConnection(ClientConfig config) throws Exception {
        this.config = config;
    }

    public void setCallback(SSLCertificateApprovalCallback callback) {
        this.callback = callback;
    }

    private class JSSProtocolSocketFactory implements SchemeLayeredSocketFactory {

        @Override
        public Socket createSocket(HttpParams params) throws IOException {
            return null;
        }

        @Override
        public Socket connectSocket(Socket sock,
                InetSocketAddress remoteAddress,
                InetSocketAddress localAddress,
                HttpParams params)
                throws IOException,
                UnknownHostException {

            // Make sure certificate database is already initialized,
            // otherwise SSLSocket will throw UnsatisfiedLinkError.
            try {
                CryptoManager.getInstance();

            } catch (NotInitializedException e) {
                throw new Error("Certificate database not initialized.", e);
            }

            String hostName = null;
            int port = 0;
            if (remoteAddress != null) {
                hostName = remoteAddress.getHostName();
                port = remoteAddress.getPort();
            }

            int localPort = 0;
            InetAddress localAddr = null;

            if (localAddress != null) {
                localPort = localAddress.getPort();
                localAddr = localAddress.getAddress();
            }

            SSLSocket socket;
            if (sock == null) {
                socket = new SSLSocket(InetAddress.getByName(hostName),
                        port,
                        localAddr,
                        localPort,
                        callback,
                        null);

            } else {
                socket = new SSLSocket(sock, hostName, callback, null);
            }

            String certNickname = config.getCertNickname();
            if (certNickname != null) {
                logger.info("Client certificate: "+certNickname);
                socket.setClientCertNickname(certNickname);
            }

            socket.addSocketListener(new SSLSocketListener() {

                @Override
                public void alertReceived(SSLAlertEvent event) {

                    int intLevel = event.getLevel();
                    SSLAlertLevel level = SSLAlertLevel.valueOf(intLevel);

                    int intDescription = event.getDescription();
                    SSLAlertDescription description = SSLAlertDescription.valueOf(intDescription);

                    if (level == SSLAlertLevel.FATAL || logger.isInfoEnabled()) {
                        logger.error(level + ": SSL alert received: " + description);
                    }
                }

                @Override
                public void alertSent(SSLAlertEvent event) {

                    int intLevel = event.getLevel();
                    SSLAlertLevel level = SSLAlertLevel.valueOf(intLevel);

                    int intDescription = event.getDescription();
                    SSLAlertDescription description = SSLAlertDescription.valueOf(intDescription);

                    if (level == SSLAlertLevel.FATAL || logger.isInfoEnabled()) {
                        logger.error(level + ": SSL alert sent: " + description);
                    }
                }

                @Override
                public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
                }

            });
            return socket;
        }

        @Override
        public boolean isSecure(Socket sock) {
            // We only use this factory in the case of SSL Connections.
            return true;
        }

        @Override
        public Socket createLayeredSocket(Socket socket, String target, int port, HttpParams params)
                throws IOException, UnknownHostException {
            // This method implementation is required to get SSL working.
            return null;
        }

    }

    public WebTarget target(String path) {
        return null;
    }

    public File getOutput() {
        return output;
    }

    public void setOutput(File output) {
        this.output = output;
    }

    @Override
    public void close() {
    }
}
