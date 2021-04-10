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
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.request.IRequest;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class CACertAddCLI extends CommandCLI {

    public static Logger logger = LoggerFactory.getLogger(CACertAddCLI.class);

    public CACertAddCLI(CLI parent) {
        super("add", "Add certificates into CA", parent);
    }

    public void createOptions() {
        Option option = new Option(null, "cert", true, "Certificate path");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "profile", true, "Certificate profile");
        option.setArgName("path");
        options.addOption(option);

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    public void execute(CommandLine cmd) throws Exception {

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.Level.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(Level.INFO);
        }

        String profileID = cmd.getOptionValue("profile");
        String certPath = cmd.getOptionValue("cert");
        String certFormat = cmd.getOptionValue("format");

        String catalinaBase = System.getProperty("catalina.base");

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();

        byte[] bytes;
        if (certPath == null) {
            // read from standard input
            bytes = IOUtils.toByteArray(System.in);

        } else {
            // read from file
            bytes = Files.readAllBytes(Paths.get(certPath));
        }

        if (certFormat == null || "PEM".equalsIgnoreCase(certFormat)) {
            bytes = Cert.parseCertificate(new String(bytes));

        } else if ("DER".equalsIgnoreCase(certFormat)) {
            // nothing to do

        } else {
            throw new Exception("Unsupported format: " + certFormat);
        }

        X509CertImpl cert = new X509CertImpl(bytes);

        X509CertInfo info = cert.getInfo();
        logger.info("Cert info:\n" + info);

        String subsystem = parent.getParent().getName();
        String subsystemConfDir = catalinaBase + File.separator + subsystem + File.separator + "conf";
        String subsystemConfigPath = subsystemConfDir + File.separator + CMS.CONFIG_FILE;
        logger.info("Loading " + subsystemConfigPath);

        CAEngineConfig cs = new CAEngineConfig(new FileConfigStore(subsystemConfigPath));
        cs.load();

        String profilePath = subsystemConfDir + File.separator + profileID;
        logger.info("Loading " + profilePath);

        PropConfigStore profileConfig = new PropConfigStore(new FileConfigStore(profilePath));
        profileConfig.load();

        String profileIDMapping = profileConfig.getString("profileIDMapping");

        DatabaseConfig dbConfig = cs.getDatabaseConfig();
        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        IPasswordStore passwordStore = IPasswordStore.create(psc);

        DBSubsystem dbSubsystem = new DBSubsystem();
        dbSubsystem.init(dbConfig, socketConfig, passwordStore);

        X509Key x509key = null;
        String[] dnsNames = null;
        boolean installAdjustValidity = false;
        CertificateExtensions extensions = new CertificateExtensions();
        String certRequestType = null;
        byte[] certRequest = null;
        String subjectName = null;

        try {
            RequestRepository requestRepository = new CertRequestRepository(dbSubsystem);
            IRequest request = requestRepository.createRequest("enrollment");

            //engine.initCertRequest(
            //        req,
            //        profile,
            //        info,
            //        x509key,
            //        dnsNames,
            //        installAdjustValidity,
            //        extensions);

            //engine.updateCertRequest(
            //        req,
            //        certRequestType,
            //        certRequest,
            //        subjectName,
            //        cert);

            requestRepository.addRequest(request);
            //RequestQueue queue = engine.getRequestQueue();
            //queue.updateRequest(req);

            CertificateRepository certificateRepository = new CertificateRepository(dbSubsystem);
            CertRecord record = certificateRepository.createCertRecord(
                    request.getRequestId(),
                    profileIDMapping,
                    cert);
            certificateRepository.addCertificateRecord(record);

        } finally {
            dbSubsystem.shutdown();
        }
    }
}
