//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;
import org.dogtagpki.nss.NSSExtensionGenerator;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.primitive.Name;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class NSSCertIssueCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSCertIssueCLI.class);

    public NSSCertIssueCLI(NSSCertCLI nssCertCLI) {
        super("issue", "Issue certificate", nssCertCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "issuer", true, "Issuer nickname (default is self-signed)");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option(null, "csr", true, "Certificate signing request");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "request-type", true, "Request type: pkcs10 (default), crmf");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "ext", true, "Certificate extensions configuration");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "subjectAltName", true, "Subject alternative name");
        option.setArgName("value");
        options.addOption(option);

        option = new Option(null, "serial", true, "Serial number (default is 128-bit random number)");
        option.setArgName("number");
        options.addOption(option);

        option = new Option(null, "months-valid", true, "DEPRECATED: Months valid");
        option.setArgName("months");
        options.addOption(option);

        option = new Option(null, "validity-length", true, "Validity length (default: 3)");
        option.setArgName("length");
        options.addOption(option);

        option = new Option(null, "validity-unit", true, "Validity unit: minute, hour, day, month (default), year");
        option.setArgName("unit");
        options.addOption(option);

        option = new Option(null, "hash", true, "Hash algorithm (default is SHA256)");
        option.setArgName("hash");
        options.addOption(option);

        option = new Option(null, "cert", true, "Certificate");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String issuerNickname = cmd.getOptionValue("issuer");
        String csrFile = cmd.getOptionValue("csr");
        String requestType = cmd.getOptionValue("request-type", "pkcs10");
        String extConf = cmd.getOptionValue("ext");
        String subjectAltName = cmd.getOptionValue("subjectAltName");
        String serialNumber = cmd.getOptionValue("serial");
        String monthsValid = cmd.getOptionValue("months-valid");
        String validityLengthStr = cmd.getOptionValue("validity-length", "3");
        String validityUnitStr = cmd.getOptionValue("validity-unit", "month");
        String hash = cmd.getOptionValue("hash", "SHA256");

        if (csrFile == null) {
            throw new Exception("Missing certificate signing request");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        ClientConfig clientConfig = mainCLI.getConfig();
        NSSDatabase nssdb = mainCLI.getNSSDatabase();

        org.mozilla.jss.crypto.X509Certificate issuer;
        if (issuerNickname == null) {
            issuer = null;

        } else {
            CryptoManager cm = CryptoManager.getInstance();
            issuer = cm.findCertByNickname(issuerNickname);
        }

        String csrPEM = new String(Files.readAllBytes(Paths.get(csrFile)));
        byte[] csrBytes = CertUtil.parseCSR(csrPEM);

        PKCS10 pkcs10 = null;
        if ("pkcs10".equalsIgnoreCase(requestType)) {
            pkcs10 = new PKCS10(csrBytes);

        } else if ("crmf".equalsIgnoreCase(requestType)) {
            SEQUENCE crmfMsgs = CryptoUtil.parseCRMFMsgs(csrBytes);
            System.out.println("Subject: " + CryptoUtil.getSubjectName(crmfMsgs));

            CertReqMsg[] msgs = CertUtil.parseCRMF(csrPEM);
            for (CertReqMsg msg : msgs) {
                CertRequest request = msg.getCertReq();
                CertTemplate template = request.getCertTemplate();
                Name name = template.getSubject();
                System.out.println("Subject: " + CryptoUtil.getSubjectName(crmfMsgs));
            }

        } else {
            throw new CLIException("Unsupported certificate request type: " + requestType);
        }

        NSSExtensionGenerator generator = new NSSExtensionGenerator();
        Extensions extensions = null;

        if (extConf != null) {
            generator.init(extConf);
        }

        if (subjectAltName != null) {
            generator.setParameter("subjectAltName", subjectAltName);
        }

        extensions = generator.createExtensions(issuer, pkcs10);

        int validityLength;
        int validityUnit;

        if (monthsValid != null) {
            logger.warn("The --months-valid option has been deprecated. Use --validity-length and --validity-unit instead.");
            validityLength = Integer.valueOf(monthsValid);
            validityUnit = Calendar.MONTH;

        } else {
            validityLength = Integer.valueOf(validityLengthStr);
            validityUnit = NSSDatabase.validityUnitFromString(validityUnitStr);
        }

        String tokenName = clientConfig.getTokenName();

        X509Certificate cert = nssdb.createCertificate(
                tokenName,
                issuer,
                pkcs10,
                serialNumber,
                validityLength,
                validityUnit,
                hash,
                extensions);

        String format = cmd.getOptionValue("format");
        byte[] bytes;

        if (format == null || "PEM".equalsIgnoreCase(format)) {
            bytes = CertUtil.toPEM(cert).getBytes();

        } else if ("DER".equalsIgnoreCase(format)) {
            bytes = cert.getEncoded();

        } else {
            throw new Exception("Unsupported format: " + format);
        }

        String filename = cmd.getOptionValue("cert");

        if (filename != null) {
            Files.write(Paths.get(filename) , bytes);

        } else {
            System.out.write(bytes);
        }
    }
}
