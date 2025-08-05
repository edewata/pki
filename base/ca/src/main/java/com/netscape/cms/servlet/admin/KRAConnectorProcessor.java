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
package com.netscape.cms.servlet.admin;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Locale;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.nss.NSSDatabase;
import org.dogtagpki.server.ca.CAConfig;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.CAService;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.connector.Connector;
import com.netscape.certsrv.connector.ConnectorConfig;
import com.netscape.certsrv.connector.ConnectorsConfig;
import com.netscape.certsrv.system.ConnectorNotFoundException;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.cms.profile.common.CAEnrollProfile;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Ade Lee
 */
public class KRAConnectorProcessor extends CAProcessor {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAConnectorProcessor.class);

    private boolean connectorExists;

    public final static String PREFIX = "ca.connector.KRA";

    public KRAConnectorProcessor(Locale locale) {
        super("kraconnector", locale);
    }

    public void init() {

        CAEngine caEngine = (CAEngine) engine;
        CAService caService = caEngine.getCAService();
        connectorExists = caService.getKRAConnector() != null;
    }

    public void removeConnector(String newHost, String newPort) throws EPropertyNotFound, EBaseException {

        if ((newHost == null) || (newPort == null)) {
            logger.error("KRAConnectorProcessor: Invalid request: Missing KRA host or port");
            throw new BadRequestException("Invalid request: Missing KRA host or port");
        }

        String hostport = newHost + ":" + newPort;
        logger.info("KRAConnectorProcessor: Removing KRA connector " + hostport);

        if (!connectorExists) {
            logger.info("KRAConnectorProcessor: No KRA connectors");
            return;
        }

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();
        CAConfig caConfig = cs.getCAConfig();
        ConnectorsConfig connectorsConfig = caConfig.getConnectorsConfig();
        ConnectorConfig kraConnectorConfig = connectorsConfig.getConnectorConfig("KRA");

        String host = kraConnectorConfig.getString("host");
        logger.info("KRAConnectorProcessor: KRA connector host: " + host);

        String port = kraConnectorConfig.getString("port");
        logger.info("KRAConnectorProcessor: KRA connector port: " + port);

        if ((host == null) || (port == null)) {
            logger.error("KRAConnectorProcessor: Invalid KRA connector configuration: Missing KRA host or port");
            throw new PKIException("Invalid KRA connector configuration: Missing KRA host or port");
        }

        if ((host.equals(newHost)) && port.equals(newPort)) {
            logger.info("KRAConnectorProcessor: Removing the last KRA connector");
            connectorsConfig.removeConnectorConfig("KRA");
            cs.commit(true);
            deleteConnector();
            return;
        }

        if (host.indexOf(' ') < 0) { // host is not a list
            logger.info("KRAConnectorProcessor: KRA connector " + hostport + " not found");
            return;
        }

        // host is a list
        String[] hostList = host.trim().split(" ");
        ArrayList<String> finalList = new ArrayList<>();
        for (String h : hostList) {
            if (! h.equals(hostport)) {
                finalList.add(h);
            }
        }

        if (finalList.size() == hostList.length) {
            logger.info("KRAConnectorProcessor: KRA connector " + hostport + " not found");
            return;
        }

        if (finalList.size() == 0) {
            logger.info("KRAConnectorProcessor: Removing the last KRA connector");
            connectorsConfig.removeConnectorConfig("KRA");
            cs.commit(true);
            deleteConnector();
            return;
        }

        if (finalList.size() == 1) {

            host = finalList.get(0).split(":")[0];
            logger.info("KRAConnectorProcessor: KRA connector host: " + host);

            port = finalList.get(0).split(":")[1];
            logger.info("KRAConnectorProcessor: KRA connector port: " + port);

            kraConnectorConfig.putString("host", host);
            kraConnectorConfig.putString("port", port);
            cs.commit(true);
            replaceConnector();
            return;
        }

        String finalString = StringUtils.join(finalList, " ");
        logger.info("KRAConnectorProcessor: KRA connector host: " + finalString);
        kraConnectorConfig.putString("host", finalString.trim());
        cs.commit(true);
        replaceConnector();
    }

    public void stopConnector() {

        CAEngine engine = CAEngine.getInstance();
        CAService caService = engine.getCAService();
        Connector kraConnector = caService.getKRAConnector();
        if (kraConnector != null) {
            kraConnector.stop();
        }
    }

    public void startConnector() {

        CAEngine engine = CAEngine.getInstance();
        CAService caService = engine.getCAService();
        Connector kraConnector = caService.getKRAConnector();
        if (kraConnector != null) {
            kraConnector.start();
        }
    }

    public void replaceConnector() throws EBaseException {
        // stop the old connector
        stopConnector();

        CAEngine engine = CAEngine.getInstance();
        CAService caService = engine.getCAService();

        CAEngineConfig cs = engine.getConfig();
        CAConfig caConfig = cs.getCAConfig();
        ConnectorsConfig connectorsConfig = caConfig.getConnectorsConfig();

        ConnectorConfig kraConnectorConfig = connectorsConfig.getConnectorConfig("KRA");
        Connector kraConnector = caService.getConnector(kraConnectorConfig);
        caService.setKRAConnector(kraConnector);

        startConnector();
    }

    public void deleteConnector() {
        stopConnector();

        CAEngine engine = CAEngine.getInstance();
        CAService caService = engine.getCAService();
        caService.setKRAConnector(null);
    }

    public void addConnector(KRAConnectorInfo info) throws Exception {

        logger.info("KRAConnectorProcessor: Adding KRA connector:");

        String newHost = info.getHost();
        logger.info("KRAConnectorProcessor: - new host: " + newHost);

        if (newHost == null) {
            logger.error("KRAConnectorProcessor: Missing KRA connector host");
            throw new BadRequestException("Missing KRA connector host");
        }

        String newPort = info.getPort();
        logger.info("KRAConnectorProcessor: - new port: " + newPort);

        if (newPort == null) {
            logger.error("KRAConnectorProcessor: Missing KRA connector host or port");
            throw new BadRequestException("Missing KRA connector host or port");
        }

        String newTransportCertNickname = info.getTransportCertNickname();
        if (newTransportCertNickname == null) {
            newTransportCertNickname = CAEnrollProfile.DEFAULT_TRANSPORT_CERT_NICKNAME;
        }
        logger.info("KRAConnectorProcessor: - new transport cert nickname: " + newTransportCertNickname);

        String newTransportCertB64 = info.getTransportCert();
        logger.info("KRAConnectorProcessor: - new transport cert: " + newTransportCertB64);

        if (newTransportCertB64 == null) {
            logger.error("KRAConnectorProcessor: Missing KRA connector transport certificate");
            throw new BadRequestException("Missing KRA connector transport certificate");
        }

        byte[] newTransportCertBytes = Utils.base64decode(newTransportCertB64);
        X509CertImpl newTransportCert = new X509CertImpl(newTransportCertBytes);

        logger.info("KRAConnectorProcessor: - new path: " + info.getUri());

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();
        CAConfig caConfig = cs.getCAConfig();
        ConnectorsConfig connectorsConfig = caConfig.getConnectorsConfig();
        ConnectorConfig kraConnectorConfig = connectorsConfig.getConnectorConfig("KRA");

        String transportCertNickname = kraConnectorConfig.getString(
                "transportCertNickname",
                CAEnrollProfile.DEFAULT_TRANSPORT_CERT_NICKNAME);
        logger.info("KRAConnectorProcessor: - current transport cert nickname: " + transportCertNickname);

        String transportCertB64 = kraConnectorConfig.getString("transportCert", null);

        NSSDatabase nssdb = new NSSDatabase();

        byte[] transportCertBytes = null;
        org.mozilla.jss.crypto.X509Certificate transportCert = null;

        if (transportCertB64 == null) {
            // get existing transport cert from NSS database
            transportCert = nssdb.getCertificate(transportCertNickname);
            if (transportCert != null) {
                transportCertBytes = transportCert.getEncoded();
                logger.info("KRAConnectorProcessor: - current transport cert in NSS database: " + transportCertB64);
            }
        } else {
            // get existing transport cert from CS.cfg
            logger.info("KRAConnectorProcessor: - current transport cert in CS.cfg: " + transportCertB64);
            transportCertBytes = Utils.base64decode(transportCertB64);
        }

        if (connectorExists) {
            String currentHost = kraConnectorConfig.getString("host");
            String currentPort = kraConnectorConfig.getString("port");

            if ((!currentHost.equals(newHost)) || (!currentPort.equals(newPort))) {
                // new and current host/port do not match

                // check transport cert
                if (!Arrays.equals(newTransportCertBytes, transportCertBytes)) {
                    // new and current certs do not match -> error
                    logger.error("KRAConnectorProcessor: KRA connector already exists");
                    throw new BadRequestException("KRA connector already exists");
                }

                logger.info("KRAConnectorProcessor: Adding {}:{} into KRA connector", newHost, newPort);
                addHostPortToConnector(kraConnectorConfig, newHost, newPort, currentHost, currentPort);

                cs.commit(true);
                replaceConnector();
                return;
            }
        }

        // connector does not exist, or existing connector is the same host/port and we are replacing it

        if (!Arrays.equals(newTransportCertBytes, transportCertBytes)) {
            // new and current certs do not match -> replace

            if (transportCertB64 == null) {
                if (transportCert != null) {
                    logger.info("KRAConnectorProcessor: Removing existing cert from NSS database");
                    nssdb.deleteCertificate(null, transportCert);
                }
            } else {
                logger.info("KRAConnectorProcessor: Removing existing cert from CS.cfg");
                kraConnectorConfig.remove("transportCert");
            }

            logger.info("KRAConnectorProcessor: Importing {} into NSS database", newTransportCertNickname);
            nssdb.addCertificate(newTransportCertNickname, newTransportCert, null);
        }

        logger.info("KRAConnectorProcessor: Storing KRA connector");
        kraConnectorConfig.putString("host", newHost);
        kraConnectorConfig.putString("port", newPort);
        kraConnectorConfig.putString("enable", info.getEnable() != null ? info.getEnable() : "true");
        kraConnectorConfig.putString("local", info.getLocal() != null ? info.getLocal(): "false");
        kraConnectorConfig.putString("timeout", info.getTimeout() != null ?  info.getTimeout() : "30");
        kraConnectorConfig.putString("uri", info.getUri() != null ? info.getUri() : "/kra/agent/kra/connector");
        kraConnectorConfig.putString("transportCertNickname", newTransportCertNickname);

        String nickname = cs.getString("ca.subsystem.nickname", "");
        String tokenname = cs.getString("ca.subsystem.tokenname", "");
        if (!CryptoUtil.isInternalToken(tokenname))
            nickname = tokenname + ":" + nickname;
        kraConnectorConfig.putString("nickName", nickname);
        cs.commit(true);

        replaceConnector();
    }

    public KRAConnectorInfo getConnectorInfo() throws EPropertyNotFound, EBaseException {

        if (!connectorExists) {
            logger.error("KRAConnectorProcessor: No KRA connectors");
            throw new ConnectorNotFoundException("No KRA connectors");
        }

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();
        CAConfig caConfig = cs.getCAConfig();
        ConnectorsConfig connectorsConfig = caConfig.getConnectorsConfig();
        ConnectorConfig kraConnectorConfig = connectorsConfig.getConnectorConfig("KRA");

        KRAConnectorInfo info = new KRAConnectorInfo();
        info.setHost(kraConnectorConfig.getString("host"));
        info.setPort(kraConnectorConfig.getString("port"));
        info.setEnable(kraConnectorConfig.getString("enable"));
        info.setLocal(kraConnectorConfig.getString("local"));
        info.setTimeout(kraConnectorConfig.getString("timeout"));
        info.setUri(kraConnectorConfig.getString("uri"));
        info.setTransportCert(kraConnectorConfig.getString("transportCert", null));
        info.setTransportCertNickname(kraConnectorConfig.getString("transportCertNickname", null));

        return info;
    }

    public void addHost(String newHost, String newPort) throws EPropertyNotFound, EBaseException {
        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();
        CAConfig caConfig = cs.getCAConfig();
        ConnectorsConfig connectorsConfig = caConfig.getConnectorsConfig();
        ConnectorConfig kraConnectorConfig = connectorsConfig.getConnectorConfig("KRA");

        if ((newHost == null) || (newPort == null)) {
            logger.error("KRAConnectorProcessor: Missing KRA connector host, port, or transport certificate");
            throw new BadRequestException("Missing KRA connector host, port, or transport certificate");
        }

        if (connectorExists) {
            String currentHost = kraConnectorConfig.getString("host");
            String currentPort = kraConnectorConfig.getString("port");

            if ((!currentHost.equals(newHost)) || (!currentPort.equals(newPort))) {
                addHostPortToConnector(kraConnectorConfig, newHost, newPort, currentHost, currentPort);
                cs.commit(true);
                replaceConnector();
            }
        } else {
            throw new BadRequestException("No KRA connectors");
        }
    }

    private void addHostPortToConnector(
            ConnectorConfig kraConnectorConfig,
            String newHost,
            String newPort,
            String currentHost,
            String currentPort) throws EBaseException {

        String hostport = newHost + ":" + newPort;
        logger.info("KRAConnectorProcessor: Adding KRA connector " + hostport);

        if (currentHost.indexOf(' ') != -1) {
            // host is a list
            String[] hostList = currentHost.trim().split(" ");
            for (String h : hostList) {
                if (h.equals(hostport)) {
                    logger.info("KRAConnectorProcessor: KRA connector for " + hostport + " already exists");
                    return;
                }
            }

            kraConnectorConfig.putString("host", currentHost + " " + hostport);
        } else {
            // host is not a list, turn it into one
            kraConnectorConfig.putString("host", currentHost + ":" + currentPort + " " + hostport);
        }
    }
}
