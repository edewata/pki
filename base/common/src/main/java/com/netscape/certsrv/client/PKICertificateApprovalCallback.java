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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

public class PKICertificateApprovalCallback implements SSLCertificateApprovalCallback {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKICertificateApprovalCallback.class);

    Collection<Integer> rejected = new HashSet<>();
    Collection<Integer> ignored = new HashSet<>();
    Collection<Integer> processed = new HashSet<>();

    public PKICertificateApprovalCallback() {
    }

    public void reject(Integer status) {
        rejected.add(status);
    }

    public void reject(Collection<Integer> statuses) {
        this.rejected.clear();
        if (statuses == null) return;
        this.rejected.addAll(statuses);
    }

    public boolean isRejected(Integer status) {
        return rejected.contains(status);
    }

    public void ignore(Integer status) {
        ignored.add(status);
    }

    public void ignore(Collection<Integer> statuses) {
        this.ignored.clear();
        if (statuses == null) return;
        this.ignored.addAll(statuses);
    }

    public boolean isIgnored(Integer status) {
        return ignored.contains(status);
    }

    // NOTE:  The following helper method defined as
    //        'public String displayReason(int reason)'
    //        should be moved into the JSS class called
    //        'org.mozilla.jss.ssl.SSLCertificateApprovalCallback'
    //        under its nested subclass called 'ValidityStatus'.

    // While all reason values should be unique, this method has been
    // written to return the name of the first defined reason that is
    // encountered which contains the requested value, or null if no
    // reason containing the requested value is encountered.
    public String displayReason(int reason) {

        for (Field f : ValidityStatus.class.getDeclaredFields()) {
            int mod = f.getModifiers();
            if (Modifier.isStatic(mod) &&
                Modifier.isPublic(mod) &&
                Modifier.isFinal(mod)) {
                try {
                    int value = f.getInt(null);
                    if (value == reason) {
                        return f.getName();
                    }
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        return null;
    }

    public String getMessage(org.mozilla.jss.crypto.X509Certificate serverCert, int reason) {

        if (reason == SSLCertificateApprovalCallback.ValidityStatus.BAD_CERT_DOMAIN) {
            return "BAD_CERT_DOMAIN encountered on '"+serverCert.getSubjectDN()+"' indicates a common-name mismatch";
        }

        if (reason == SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER) {
            return "UNTRUSTED_ISSUER encountered on '" +
                    serverCert.getSubjectDN() + "' indicates a non-trusted CA cert '" +
                    serverCert.getIssuerDN() + "'";
        }

        if (reason == SSLCertificateApprovalCallback.ValidityStatus.UNKNOWN_ISSUER) {
            return "UNKNOWN_ISSUER encountered on '" +
                    serverCert.getSubjectDN() + "' indicates an unknown CA cert '" +
                    serverCert.getIssuerDN() + "'";
        }

        if (reason == SSLCertificateApprovalCallback.ValidityStatus.CA_CERT_INVALID) {
            return "CA_CERT_INVALID encountered on '"+serverCert.getSubjectDN()+"' results in a denied SSL server cert!";
        }

        String reasonName = displayReason(reason);
        if (reasonName != null) {
            return reasonName+" encountered on '"+serverCert.getSubjectDN()+"' results in a denied SSL server cert!";
        }

        return "Unknown/undefined reason "+reason+" encountered on '"+serverCert.getSubjectDN()+"' results in a denied SSL server cert!";
    }

    public boolean trustCert(org.mozilla.jss.crypto.X509Certificate serverCert) {
        try {
            System.err.print("Trust this certificate (y/N)? ");

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String line = reader.readLine().trim();

            // require explicit confirmation to trust certificate
            if (!line.equalsIgnoreCase("Y"))
                return false;

            Principal subjectDN = serverCert.getSubjectDN();
            String nickname = subjectDN.getName();

            logger.info("Importing certificate as " + nickname);
            CryptoManager manager = CryptoManager.getInstance();
            manager.importCertToPerm(serverCert, nickname);

            logger.info("Trusting certificate");
            PK11Cert internalCert = (PK11Cert) serverCert;
            internalCert.setSSLTrust(PK11Cert.TRUSTED_PEER);

            return true;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Callback to approve or deny returned SSL server cert.
    // Right now, simply approve the cert.
    @Override
    public boolean approve(X509Certificate cert, ValidityStatus status) {

        org.mozilla.jss.crypto.X509Certificate serverCert = (org.mozilla.jss.crypto.X509Certificate) cert;

        logger.info("Server certificate:");
        logger.info("- subject: " + serverCert.getSubjectDN());
        logger.info("- issuer: " + serverCert.getIssuerDN());

        // If there are no items in the Enumeration returned by
        // getReasons(), you can assume that the certificate is
        // trustworthy, and return true to allow the connection to
        // continue, or you can continue to make further tests of
        // your own to determine trustworthiness.
        Enumeration<?> errors = status.getReasons();

        boolean approval = true;
        boolean prompt = false;

        while (errors.hasMoreElements()) {
            SSLCertificateApprovalCallback.ValidityItem item =
                    (SSLCertificateApprovalCallback.ValidityItem) errors.nextElement();

            int reason = item.getReason();
            if (processed.contains(reason)) {
                // status already processed, skip
                continue;
            }

            processed.add(reason);

            if (isRejected(reason)) {
                System.err.println("ERROR: " + getMessage(serverCert, reason));
                approval = false;

            } else if (isIgnored(reason)) {
                // Ignore validity status

            } else if (reason == SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER
                    || reason == SSLCertificateApprovalCallback.ValidityStatus.UNKNOWN_ISSUER) {
                // Issue a WARNING, but allow this process
                // to continue since we haven't installed a trusted CA
                // cert for this operation.
                System.err.println("WARNING: " + getMessage(serverCert, reason));
                prompt = true;

            } else if (reason == SSLCertificateApprovalCallback.ValidityStatus.BAD_CERT_DOMAIN) {
                // Issue a WARNING, but allow this process to continue on
                // common-name mismatches.
                System.err.println("WARNING: " + getMessage(serverCert, reason));

            } else if (reason == SSLCertificateApprovalCallback.ValidityStatus.CA_CERT_INVALID) {
                // Set approval false to deny this
                // certificate so that the connection is terminated.
                // (Expect an IOException on the outstanding
                //  read()/write() on the socket).
                System.err.println("ERROR: " + getMessage(serverCert, reason));
                approval = false;

            } else {
                // Set approval false to deny this certificate so that
                // the connection is terminated. (Expect an IOException
                // on the outstanding read()/write() on the socket).
                System.err.println("ERROR: " + getMessage(serverCert, reason));
                approval = false;
            }
        }

        if (prompt && !trustCert(serverCert)) {
            approval = false;
        }

        return approval;
    }
}
