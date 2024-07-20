//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.client;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Arrays;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.provider.javax.crypto.JSSKeyManager;
import org.mozilla.jss.provider.javax.crypto.JSSTrustManager;
import org.mozilla.jss.ssl.SSLAlertDescription;
import org.mozilla.jss.ssl.SSLAlertEvent;
import org.mozilla.jss.ssl.SSLAlertLevel;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLSocketListener;
import org.mozilla.jss.ssl.javax.JSSSocket;
import org.mozilla.jss.ssl.javax.JSSSocketFactory;

import com.netscape.certsrv.client.PKIConnection;

/**
 * This class provides non-blocking socket factory for PKIConnection.
 */
public class NonBlockingSocketFactory extends JSSSocketFactory {

    PKIConnection connection;

    public NonBlockingSocketFactory(PKIConnection connection, String protocol, JSSKeyManager km, X509TrustManager[] tms) {
        super(protocol, km, tms);
        this.connection = connection;
    }

    @Override
    public JSSSocket createSocket(
            Socket socket,
            String host,
            int port,
            boolean autoClose)
            throws IOException {

        SSLSocketFactory socketFactory;
        try {
            CryptoManager.getInstance();

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("NssX509", "Mozilla-JSS");
            KeyManager[] kms = kmf.getKeyManagers();

            // Create JSSTrustManager since the default JSSNativeTrustManager
            // does not support hostname and callback.
            //
            // JSSTrustManager currently does not support cert validation
            // with OCSP and CRL.
            //
            // TODO: Fix JSSTrustManager to support OCSP and CRL,
            // then replace DefaultSocketFactory with this class.

            JSSTrustManager trustManager = new JSSTrustManager();
            trustManager.setHostname(host);
            trustManager.setCallback(connection.getCallback());

            TrustManager[] tms = new TrustManager[] { trustManager };

            SSLContext ctx = SSLContext.getInstance("TLS", "Mozilla-JSS");
            ctx.init(kms, tms, null);

            socketFactory = ctx.getSocketFactory();

        } catch (Exception e) {
            throw new IOException("Unable to create SSL socket factory: " + e.getMessage(), e);
        }

        JSSSocket jssSocket;
        try {
            if (socket == null) {
                PKIConnection.logger.info("Creating new SSL socket");
                jssSocket = (JSSSocket) socketFactory.createSocket(
                        InetAddress.getByName(host),
                        port);

            } else {
                PKIConnection.logger.info("Creating SSL socket with existing socket");
                jssSocket = (JSSSocket) socketFactory.createSocket(
                        socket,
                        host,
                        port,
                        autoClose);
            }

        } catch (Exception e) {
            throw new IOException("Unable to create SSL socket: " + e.getMessage(), e);
        }

        jssSocket.setUseClientMode(true);

        String certNickname = connection.getConfig().getCertNickname();
        if (certNickname != null) {
            PKIConnection.logger.info("Client certificate: "+certNickname);
            jssSocket.setCertFromAlias(certNickname);
        }

        jssSocket.getEngine().setListeners(Arrays.asList(new SSLSocketListener() {

            @Override
            public void alertReceived(SSLAlertEvent event) {

                int intLevel = event.getLevel();
                SSLAlertLevel level = SSLAlertLevel.valueOf(intLevel);

                int intDescription = event.getDescription();
                SSLAlertDescription description = SSLAlertDescription.valueOf(intDescription);

                if (level == SSLAlertLevel.FATAL || PKIConnection.logger.isInfoEnabled()) {
                    PKIConnection.logger.error(level + ": SSL alert received: " + description);
                }
            }

            @Override
            public void alertSent(SSLAlertEvent event) {

                int intLevel = event.getLevel();
                SSLAlertLevel level = SSLAlertLevel.valueOf(intLevel);

                int intDescription = event.getDescription();
                SSLAlertDescription description = SSLAlertDescription.valueOf(intDescription);

                if (level == SSLAlertLevel.FATAL || PKIConnection.logger.isInfoEnabled()) {
                    PKIConnection.logger.error(level + ": SSL alert sent: " + description);
                }
            }

            @Override
            public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
            }
        }));

        jssSocket.startHandshake();

        return jssSocket;
    }
}
