//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.cli;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.IOUtils;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.Level;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attribute;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attributes;
import org.mozilla.jss.netscape.security.pkcs.PKCS9Attribute;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class CACertRequestImportCLI extends CommandCLI {

    public static Logger logger = LoggerFactory.getLogger(CACertRequestImportCLI.class);

    public CACertRequestImportCLI(CLI parent) {
        super("import", "Import certificate request into CA", parent);
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "request", true, "Certificate request path");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate request format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "type", true, "Request type: pkcs10 (default), crmf");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "profile", true, "Profile ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "dns-names", true, "DNS names");
        option.setArgName("names");
        options.addOption(option);

        options.addOption(null, "adjust-validity", false, "Adjust validity");

        option = new Option(null, "output-format", true, "Output format: text (default), json.");
        option.setArgName("format");
        options.addOption(option);

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    public CertificateExtensions createRequestExtensions(PKCS10 pkcs10) throws Exception {

        PKCS10Attributes attrs = pkcs10.getAttributes();
        PKCS10Attribute extsAttr = attrs.getAttribute(CertificateExtensions.NAME);

        CertificateExtensions extensions;

        if (extsAttr != null && extsAttr.getAttributeId().equals(PKCS9Attribute.EXTENSION_REQUEST_OID)) {

            Extensions exts = (Extensions) extsAttr.getAttributeValue();

            // convert Extensions into CertificateExtensions
            DerOutputStream os = new DerOutputStream();
            exts.encode(os);
            DerInputStream is = new DerInputStream(os.toByteArray());

            extensions = new CertificateExtensions(is);

        } else {
            extensions = new CertificateExtensions();
        }

        return extensions;
    }

    public void createRequestRecord(
            CertRequestRepository requestRepository,
            Request request,
            String requestType,
            byte[] binRequest,
            X500Name subjectName,
            String profileID,
            String profileIDMapping,
            String profileSetIDMapping,
            X509Key x509key,
            String[] dnsNames,
            boolean adjustValidity,
            CertificateExtensions requestExtensions) throws Exception {

        logger.info("Creating request record " + request.getRequestId().toHexString());

        request.setExtData("profile", "true");
        request.setExtData("requestversion", "1.0.0");
        request.setExtData("req_seq_num", "0");

        request.setExtData(EnrollProfile.REQUEST_EXTENSIONS, requestExtensions);

        request.setExtData("requesttype", "enrollment");
        request.setExtData("requestor_name", "");
        request.setExtData("requestor_email", "");
        request.setExtData("requestor_phone", "");
        request.setExtData("profileRemoteHost", "");
        request.setExtData("profileRemoteAddr", "");
        request.setExtData("requestnotes", "");
        request.setExtData("isencryptioncert", "false");
        request.setExtData("profileapprovedby", "system");

        logger.debug("- type: " + requestType);
        request.setExtData("cert_request_type", requestType);

        if (binRequest != null) {
            String b64CertRequest = CryptoUtil.base64Encode(binRequest);
            String pemCertRequest = CryptoUtil.reqFormat(b64CertRequest);
            logger.debug("- request:\n" + pemCertRequest);
            request.setExtData("cert_request", pemCertRequest);
        }

        if (subjectName != null) {
            logger.debug("- subject: " + subjectName);
            request.setExtData("subject", subjectName.toString());
        }

        if (dnsNames != null) {

            logger.info("SAN extension:");

            // Dynamically inject the SubjectAlternativeName extension to a
            // local/self-signed master CA's request for its SSL Server Certificate.
            //
            // Since this information may vary from instance to
            // instance, obtain the necessary information from the
            // 'service.sslserver.san' value(s) in the instance's
            // CS.cfg, process these values converting each item into
            // its individual SubjectAlternativeName components, and
            // inject these values into the local request.

            int i = 0;
            for (String dnsName : dnsNames) {
                logger.info("- " + dnsName);
                request.setExtData("req_san_pattern_" + i, dnsName);
                i++;
            }
        }

        request.setExtData("req_key", x509key.toString());

        String origProfileID = profileID;
        int idx = origProfileID.lastIndexOf('.');
        if (idx > 0) {
            origProfileID = origProfileID.substring(0, idx);
        }

        // store original profile ID in cert request
        request.setExtData("origprofileid", origProfileID);

        // store mapped profile ID for renewal
        request.setExtData("profileid", profileIDMapping);
        request.setExtData("profilesetid", profileSetIDMapping);

        if (adjustValidity) {
            // (applies to non-CA-signing cert only)
            // installAdjustValidity tells ValidityDefault to adjust the
            // notAfter value to that of the CA's signing cert if needed
            request.setExtData("installAdjustValidity", "true");
        }

        requestRepository.updateRequest(request);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.Level.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(Level.INFO);
        }

        if (!cmd.hasOption("cert")) {
            throw new Exception("Missing certificate");
        }

        String requestPath = cmd.getOptionValue("request");
        String requestFormat = cmd.getOptionValue("format");

        byte[] bytes;
        if (requestPath == null) {
            // read from standard input
            bytes = IOUtils.toByteArray(System.in);

        } else {
            // read from file
            bytes = Files.readAllBytes(Paths.get(requestPath));
        }

        if (requestFormat == null || "PEM".equalsIgnoreCase(requestFormat)) {
            bytes = Cert.parseCertificate(new String(bytes));

        } else if ("DER".equalsIgnoreCase(requestFormat)) {
            // nothing to do

        } else {
            throw new Exception("Unsupported format: " + requestFormat);
        }

        String requestType = cmd.getOptionValue("type", "pkcs10");

        logger.info("Importing " + requestType + " request");

        X500Name subjectName;
        X509Key x509key;
        CertificateExtensions requestExtensions;

        if (requestType.equals("crmf")) {
            SEQUENCE crmfMsgs = CryptoUtil.parseCRMFMsgs(bytes);
            subjectName = CryptoUtil.getSubjectName(crmfMsgs);
            x509key = CryptoUtil.getX509KeyFromCRMFMsgs(crmfMsgs);
            requestExtensions = new CertificateExtensions();

        } else if (requestType.equals("pkcs10")) {
            PKCS10 pkcs10 = new PKCS10(bytes);
            subjectName = pkcs10.getSubjectName();
            x509key = pkcs10.getSubjectPublicKeyInfo();
            requestExtensions = createRequestExtensions(pkcs10);

        } else {
            throw new Exception("Certificate request type not supported: " + requestType);
        }

        String catalinaBase = System.getProperty("catalina.base");

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();

        String subsystem = parent.getParent().getName();
        String confDir = catalinaBase + File.separator + subsystem + File.separator + "conf";
        String configFile = confDir + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStore(configFile);
        CAEngineConfig cs = new CAEngineConfig(storage);
        cs.load();

        if (!cmd.hasOption("profile")) {
            throw new Exception("Missing profile ID");
        }

        String profileID = cmd.getOptionValue("profile");

        String instanceRoot = cs.getInstanceDir();
        String configurationRoot = cs.getString("configurationRoot");
        String profilePath = instanceRoot + configurationRoot + profileID;

        logger.info("Loading " + profilePath);
        ConfigStorage profileStorage = new FileConfigStore(profilePath);
        IConfigStore profileConfig = new PropConfigStore(profileStorage);
        profileConfig.load();

        DatabaseConfig dbConfig = cs.getDatabaseConfig();
        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        IPasswordStore passwordStore = IPasswordStore.create(psc);

        String value = cmd.getOptionValue("dns-names");
        String[] dnsNames = null;
        if (value != null) {
            dnsNames = value.split(",");
        }

        value = cmd.getOptionValue("adjust-validity", "false");
        boolean adjustValidity = Boolean.parseBoolean(value);

        DBSubsystem dbSubsystem = new DBSubsystem();
        dbSubsystem.init(dbConfig, socketConfig, passwordStore);

        try {
            CertRequestRepository requestRepository = new CertRequestRepository(dbSubsystem);
            requestRepository.init();

            RequestId requestID = requestRepository.createRequestID();
            Request request = requestRepository.createRequest(requestID, "enrollment");

            createRequestRecord(
                    requestRepository,
                    request,
                    requestType,
                    bytes,
                    subjectName,
                    profileConfig.getString("id"),
                    profileConfig.getString("profileIDMapping"),
                    profileConfig.getString("profileSetIDMapping"),
                    x509key,
                    dnsNames,
                    adjustValidity,
                    requestExtensions);

            String outputFormat = cmd.getOptionValue("output-format", "text");

            if (outputFormat.equalsIgnoreCase("json")) {
                System.out.println(requestID.toJSON());

            } else if (outputFormat.equalsIgnoreCase("text")) {
                System.out.println("  Request ID: " + requestID);

            } else {
                throw new Exception("Unsupported output format: " + outputFormat);
            }

        } finally {
            dbSubsystem.shutdown();
        }
    }
}
