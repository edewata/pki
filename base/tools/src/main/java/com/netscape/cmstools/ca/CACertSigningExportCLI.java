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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.ca;

import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.ca.CASystemCertClient;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKICertificateApprovalCallback;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class CACertSigningExportCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertSigningExportCLI.class);

    public CACertCLI certCLI;

    public CACertSigningExportCLI(CACertCLI certCLI) {
        super("signing-export", "Export CA signing certificate", certCLI);
        this.certCLI = certCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option("U", true, "Server URL");
        option.setArgName("uri");
        options.addOption(option);

        option = new Option(null, "skip-revocation-check", false, "Do not perform revocation check");
        options.addOption(option);

        option = new Option(null, "reject-cert-status", true, "Comma-separated list of rejected certificate validity statuses");
        option.setArgName("list");
        options.addOption(option);

        option = new Option(null, "ignore-cert-status", true, "Comma-separated list of ignored certificate validity statuses");
        option.setArgName("list");
        options.addOption(option);

        option = new Option(null, "ignore-banner", false, "Ignore access banner");
        options.addOption(option);

        option = new Option(null, "output-format", true, "Output format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "output-file", true, "Output file");
        option.setArgName("file");
        options.addOption(option);

        options.addOption(null, "pkcs7", false, "Export PKCS #7 certificate chain");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client;

        String serverURL = cmd.getOptionValue("U");
        if (serverURL != null) {
            // create new PKIClient

            ClientConfig config = new ClientConfig(mainCLI.config);
            config.setServerURL(serverURL);

            boolean skipRevocationCheck = cmd.hasOption("skip-revocation-check");
            config.setCertRevocationVerify(!skipRevocationCheck);

            String list = cmd.getOptionValue("reject-cert-status");
            Collection<Integer> rejectedCertStatuses = new ArrayList<>();
            mainCLI.convertCertStatusList(list, rejectedCertStatuses);

            list = cmd.getOptionValue("ignore-cert-status");
            Collection<Integer> ignoredCertStatuses = new ArrayList<>();
            mainCLI.convertCertStatusList(list, ignoredCertStatuses);

            PKICertificateApprovalCallback callback = new PKICertificateApprovalCallback();
            callback.reject(rejectedCertStatuses);
            callback.ignore(ignoredCertStatuses);

            boolean ignoreBanner = cmd.hasOption("ignore-banner");

            client = mainCLI.connect(config, callback, ignoreBanner);

        } else {
            // use shared PKIClient
            client = mainCLI.getClient();
        }

        CASystemCertClient certClient = new CASystemCertClient(client, "ca");
        CertData certData = certClient.getSigningCert();

        String outputFormat = cmd.getOptionValue("output-format");
        byte[] bytes;

        if (cmd.hasOption("pkcs7")) {

            String certChain = certData.getPkcs7CertChain();
            PKCS7 pkcs7 = new PKCS7(Utils.base64decode(certChain));

            if (outputFormat == null || "PEM".equalsIgnoreCase(outputFormat)) {
                bytes = pkcs7.toPEMString().getBytes();

            } else if ("DER".equalsIgnoreCase(outputFormat)) {
                bytes = pkcs7.getBytes();

            } else {
                throw new Exception("Unsupported format: " + outputFormat);
            }

        } else {

            if (outputFormat == null || "PEM".equalsIgnoreCase(outputFormat)) {
                bytes = certData.getEncoded().getBytes();

            } else if ("DER".equalsIgnoreCase(outputFormat)) {
                bytes = Cert.parseCertificate(certData.getEncoded());

            } else {
                throw new Exception("Unsupported format: " + outputFormat);
            }
        }

        String outputFile = cmd.getOptionValue("output-file");

        if (outputFile != null) {
            try (FileOutputStream out = new FileOutputStream(outputFile)) {
                out.write(bytes);
            }

        } else {
            System.out.write(bytes);
        }
    }
}
