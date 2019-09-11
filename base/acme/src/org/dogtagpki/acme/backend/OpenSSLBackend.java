//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.backend;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.commons.codec.binary.Base64;
import org.dogtagpki.acme.ACMERevocation;
import org.dogtagpki.acme.server.ACMEEngine;
import org.dogtagpki.cli.CLIException;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

/**
 * @author Endi S. Dewata
 */
public class OpenSSLBackend extends ACMEBackend {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(OpenSSLBackend.class);

    private String enrollmentCommand;
    private String revocationCommand;
    private String caConf;
    private String extConf;
    private String caCert;
    private String caKey;

    public String getEnrollmentCommand() {
        return enrollmentCommand;
    }

    public void setEnrollmentCommand(String enrollmentCommand) {
        this.enrollmentCommand = enrollmentCommand;
    }

    public String getRevocationCommand() {
        return revocationCommand;
    }

    public void setRevocationCommand(String revocationCommand) {
        this.revocationCommand = revocationCommand;
    }

    public String getCaConf() {
        return caConf;
    }

    public void setCaConf(String caConf) {
        this.caConf = caConf;
    }

    public String getExtConf() {
        return extConf;
    }

    public void setExtConf(String extConf) {
        this.extConf = extConf;
    }

    public String getCert() {
        return caCert;
    }

    public void setCert(String cert) {
        this.caCert = cert;
    }

    public String getProfile() {
        return caKey;
    }

    public void setProfile(String profile) {
        this.caKey = profile;
    }

    public void init() {
        enrollmentCommand = config.getParameter("enrollment");
        revocationCommand = config.getParameter("revocation");
        caConf = config.getParameter("ca_conf");
        extConf = config.getParameter("ext_conf");
        caCert = config.getParameter("ca_cert");
        caKey = config.getParameter("ca_key");
    }

    public String issueCertificate(String csr) throws Exception {

        logger.info("Issuing certificate");

        logger.info(" - CA cert: " + caCert);
        logger.info(" - CA key: " + caKey);

        //logger.info("Loading CA certificate from " + caCert);
        //String caCertPEM = new String(Files.readAllBytes(Paths.get(caCert)));
        //logger.info(caCertPEM);

        StringWriter sw = new StringWriter();

        try (PrintWriter out = new PrintWriter(sw, true)) {
            byte[] csrBytes = Utils.base64decode(csr);
            out.println(Cert.REQUEST_HEADER);
            out.print(Utils.base64encode(csrBytes, true));
            out.println(Cert.REQUEST_FOOTER);
        }

        csr = sw.toString();

        File tmpCsrFile = File.createTempFile("pki-acme-openssl-enrollment-", ".csr");
        File tmpCertFile = File.createTempFile("pki-acme-openssl-enrollment-", ".crt");

        String[] cmd;

        if (enrollmentCommand != null) {
            String c = enrollmentCommand.replace("{input}", tmpCsrFile.getAbsolutePath());
            c = c.replace("{output}", tmpCertFile.getAbsolutePath());
            cmd = c.split("\\s+");

        } else if (caConf != null) {
            cmd = new String[] {
                    "/usr/bin/openssl",
                    "ca",
                    "-config", caConf,
                    "-extfile", extConf,
                    "-in", tmpCsrFile.getAbsolutePath(),
                    "-out", tmpCertFile.getAbsolutePath(),
                    "-notext",
                    "-batch"
            };

        } else {
            cmd = new String[] {
                    "/usr/bin/openssl",
                    "x509",
                    "-req",
                    "-CA", caCert,
                    "-CAkey", caKey,
                    "-CAcreateserial",
                    "-in", tmpCsrFile.getAbsolutePath(),
                    "-out", tmpCertFile.getAbsolutePath()
            };
        }

        ACMEEngine engine = ACMEEngine.getInstance();
        String certsDir = System.getProperty("catalina.base") + "/conf/" + engine.getName() + "/certs";

        try {
            logger.info("Storing CSR to " + tmpCsrFile);
            logger.info(csr);

            Files.write(tmpCsrFile.toPath(), csr.getBytes());

            execute(cmd);

            logger.info("Loading certificat from " + tmpCertFile);
            String certPEM = new String(Files.readAllBytes(tmpCertFile.toPath()));
            logger.info(certPEM);

            byte[] certBytes = Cert.parseCertificate(certPEM);

            X509CertImpl certImpl = new X509CertImpl(certBytes);
            BigInteger serialNumber = certImpl.getSerialNumber();
            String sn = serialNumber.toString(16).toUpperCase();
            if (sn.length() % 2 == 1) {
                sn = "0" + sn;
            }
            logger.info("Serial number: " + sn);

            String certID = Base64.encodeBase64URLSafeString(serialNumber.toByteArray());
/*
            String certPath = certsDir + "/" + certID + ".pem";

            try (FileWriter fw = new FileWriter(certPath, true);
                    BufferedWriter bw = new BufferedWriter(fw);
                    PrintWriter out = new PrintWriter(bw)) {
                out.print(certPEM);
                out.print(caCertPEM);
            }
*/
            return certID;

        } finally {
            tmpCertFile.delete();
            tmpCsrFile.delete();
        }
    }

    public String getCertificateChain(String certID) throws Exception {

        BigInteger serialNumber = new BigInteger(1, Base64.decodeBase64(certID));
        String sn = serialNumber.toString(16).toUpperCase();
        if (sn.length() % 2 == 1) {
            sn = "0" + sn;
        }
        logger.info("Serial number: " + sn);

        ACMEEngine engine = ACMEEngine.getInstance();
        String catalinaBase = System.getProperty("catalina.base");
        String certsDir = catalinaBase + "/conf/" + engine.getName() + "/certs";
        Path certPath = Paths.get(certsDir + "/" + sn + ".pem");

        logger.info("Loading certificate chain from " + certPath);
        String certPEM = new String(Files.readAllBytes(certPath));
        logger.info(certPEM);

        logger.info("Loading CA certificate from " + caCert);
        String caCertPEM = new String(Files.readAllBytes(Paths.get(caCert)));
        logger.info(caCertPEM);

        StringWriter sw = new StringWriter();

        try (PrintWriter out = new PrintWriter(sw, true)) {
            out.print(certPEM);
            out.print(caCertPEM);
        }

        return sw.toString();
    }

    public void revokeCert(ACMERevocation revocation) throws Exception {

        String certBase64 = revocation.getCertificate();
        byte[] certBytes = Utils.base64decode(certBase64);
        Integer reason = revocation.getReason();

        StringWriter sw = new StringWriter();

        try (PrintWriter out = new PrintWriter(sw, true)) {
            out.println(Cert.HEADER);
            out.print(Utils.base64encode(certBytes, true));
            out.println(Cert.FOOTER);
        }

        String certPEM = sw.toString();

        logger.info("Certificate:\n" + certPEM);
        logger.info("Reason: " + reason);

        File tmpCertFile = File.createTempFile("pki-acme-openssl-revoke-", ".crt");

        String[] cmd = new String[] {
                "/usr/bin/openssl",
                "ca",
                "-config", caConf,
                "-revoke", tmpCertFile.getAbsolutePath()
        };

        try {
            logger.info("Storing cert into " + tmpCertFile);
            Files.write(tmpCertFile.toPath(), certPEM.getBytes());

            logger.info("Revoking certificate");
            execute(cmd);

        } finally {
            tmpCertFile.delete();
        }
    }

    public void execute(String[] command) throws CLIException, IOException, InterruptedException {

        StringBuilder sb = new StringBuilder();

        for (String c : command) {

            boolean quote = c.contains(" ");

            sb.append(" ");

            if (quote) sb.append("\"");
            sb.append(c);
            if (quote) sb.append("\"");
        }

        logger.info("Command: " + sb);

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.inheritIO();
        Process p = pb.start();

        int rc = p.waitFor();

        if (rc != 0) {
            throw new CLIException("Command failed. RC: " + rc, rc);
        }
    }
}
