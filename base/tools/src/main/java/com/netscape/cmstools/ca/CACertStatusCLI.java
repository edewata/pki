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

package com.netscape.cmstools.ca;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.asn1.GeneralizedTime;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.ocsp.BasicOCSPResponse;
import com.netscape.cmsutil.ocsp.CertID;
import com.netscape.cmsutil.ocsp.CertStatus;
import com.netscape.cmsutil.ocsp.GoodInfo;
import com.netscape.cmsutil.ocsp.OCSPProcessor;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.cmsutil.ocsp.ResponseData;
import com.netscape.cmsutil.ocsp.RevokedInfo;
import com.netscape.cmsutil.ocsp.SingleResponse;
import com.netscape.cmsutil.ocsp.UnknownInfo;

/**
 * @author Endi S. Dewata
 */
public class CACertStatusCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertStatusCLI.class);

    public CACertCLI certCLI;

    public CACertStatusCLI(CACertCLI certCLI) {
        super("status", "Check certificate status", certCLI);
        this.certCLI = certCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [serial number] [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "ca-cert", true, "CA certificate nickname");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option(null, "ocsp", true, "OCSP URL or path (default: https://<hostname>:<port>/ca/ocsp");
        option.setArgName("URL");
        options.addOption(option);

        option = new Option(null, "input", true, "DER-encoded OCSP request file");
        option.setArgName("path");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        String caCertNickname = cmd.getOptionValue("ca-cert");
        String ocspURL = cmd.getOptionValue("ocsp");
        String inputFilename = cmd.getOptionValue("input");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = getClient();
        CAClient caClient = new CAClient(client);
        CACertClient certClient = new CACertClient(caClient);
        AuthorityClient authorityClient = new AuthorityClient(caClient);

        ClientConfig config = getConfig();

        if (ocspURL == null) {
            // use CA's built-in OCSP responder URL
            ocspURL = config.getServerURL() + "/ca/ocsp";

        } else if (ocspURL.startsWith("/")) {
            // prepend server URL to the path
            ocspURL = config.getServerURL() + ocspURL;
        }

        OCSPProcessor processor = new OCSPProcessor();
        processor.setURL(ocspURL);

        OCSPRequest request;

        if (inputFilename != null) {
            logger.info("Loading OCSP request from " + inputFilename);
            byte[] data = Files.readAllBytes(Paths.get(inputFilename));
            request = processor.createRequest(data);

        } else if (caCertNickname != null) {

            if (cmdArgs.length < 1) {
                throw new Exception("Missing certificate serial number");
            }

            CertId certID = new CertId(cmdArgs[0]);

            logger.info("Creating OCSP request for cert " + certID.toHexString());
            request = processor.createRequest(caCertNickname, certID.toBigInteger());

        } else {

            if (cmdArgs.length < 1) {
                throw new Exception("Missing certificate serial number");
            }

            CertId certID = new CertId(cmdArgs[0]);

            logger.info("Retrieving cert " + certID.toHexString() + " from CA");
            CertData certData = certClient.getCert(certID);

            String subjectDN = certData.getSubjectDN();
            logger.debug("- subject DN: " + subjectDN);

            String issuerDN = certData.getIssuerDN();
            logger.debug("- issuer DN: " + issuerDN);

            logger.info("Finding CAs by issuer DN");
            Collection<AuthorityData> authorities = authorityClient.findCAs(null, null, issuerDN, null);

            if (authorities.size() == 0) {
                throw new CLIException("Unknown certificate issuer: " + issuerDN);
            }

            // get the first CA
            AuthorityData authorityData = authorities.iterator().next();
            BigInteger issuerSerialNumber = authorityData.getSerial();
            CertId issuerCertID = new CertId(issuerSerialNumber);

            logger.info("Retrieving CA cert " + issuerCertID.toHexString());
            CertData caCertData = certClient.getCert(issuerCertID);

            // parse CA cert
            String pemCert = caCertData.getEncoded();
            byte[] binCert = Cert.parseCertificate(pemCert);

            X509CertImpl caCert = new X509CertImpl(binCert);

            X500Name caDN = caCert.getSubjectName();
            X509Key caKey = (X509Key) caCert.getPublicKey();

            logger.info("Creating OCSP request for cert " + certID.toHexString());
            request = processor.createRequest(caDN, caKey, certID.toBigInteger());
        }

        logger.info("Submitting OCSP request to " + ocspURL);
        OCSPResponse response;
        try {
            response = processor.submitRequest(request);
        } catch (Exception e) {
            throw new CLIException("Unable to submit OCSP request: " + e.getMessage());
        }

        // parse OCSP response
        byte[] binResponse = response.getResponseBytes().getResponse().toByteArray();
        BasicOCSPResponse basic = (BasicOCSPResponse)BasicOCSPResponse.getTemplate().decode(
                new ByteArrayInputStream(binResponse));

        ResponseData rd = basic.getResponseData();

        // TODO: process all responses
        SingleResponse sr = rd.getResponseAt(0);

        CertID certID = sr.getCertID();
        INTEGER serialNumber = certID.getSerialNumber();
        System.out.println("  Serial Number: " + new CertId(serialNumber).toHexString());

        CertStatus status = sr.getCertStatus();

        if (status instanceof GoodInfo) {
            System.out.println("  Status: Good");

        } else if (status instanceof UnknownInfo) {
            System.out.println("  Status: Unknown");

        } else if (status instanceof RevokedInfo) {
            System.out.println("  Status: Revoked");
            RevokedInfo info = (RevokedInfo) status;
            System.out.println("  Revoked On: " + info.getRevocationTime().toDate());
        }

        GeneralizedTime thisUpdate = sr.getThisUpdate();
        if (thisUpdate != null) {
            System.out.println("  This Update: " + thisUpdate.toDate());
        }

        GeneralizedTime nextUpdate = sr.getNextUpdate();
        if (nextUpdate != null) {
            System.out.println("  Next Update: " + nextUpdate.toDate());
        }
    }
}
