//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.client;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectAlternativeNameExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.provider.javax.crypto.JSSTrustManager;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback.ValidityStatus;

/**
 * @author Endi S. Dewata
 */
public class PKITrustManager extends JSSTrustManager {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKITrustManager.class);

    String hostname;

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public boolean verifyHostname(X509Certificate cert) throws Exception {

        logger.info("PKITrustManager: verifyHostname()");
        logger.info("PKITrustManager: Subject: " + cert.getSubjectX500Principal());

        X509CertImpl certImpl = new X509CertImpl(cert.getEncoded());
        SubjectAlternativeNameExtension sanExt = (SubjectAlternativeNameExtension) certImpl.getExtension(PKIXExtensions.SubjectAlternativeName_Id.toString());

        if (sanExt != null) {
            logger.info("PKITrustManager: Verifying SAN extension");

            Set<String> dnsNames = CertUtil.getDNSNames(sanExt);
            for (String dnsName : dnsNames) {
                logger.info("PKITrustManager: - dns: " + dnsName);
            }

            return dnsNames.contains(hostname);
        }

        logger.info("PKITrustManager: Verifying CN attribute");

        X509CertInfo info = certImpl.getInfo();
        CertificateSubjectName subject = (CertificateSubjectName) info.get(X509CertInfo.SUBJECT);
        X500Name dn = (X500Name) subject.get(CertificateSubjectName.DN_NAME);

        List<String> cns = dn.getAttributesForOid(X500Name.commonName_oid);
        if (cns == null) {
            return false;
        }

        for (String cn : cns) {
            logger.info("PKITrustManager: - cn: " + cn);
        }

        return cns.contains(hostname);
    }

    @Override
    public void checkCertChain(X509Certificate[] certChain, String keyUsage, ValidityStatus status) throws Exception {

        X509Certificate leafCert = certChain[certChain.length - 1];

        if (verifyHostname(leafCert)) {
            logger.info("PKITrustManager: Valid cert domain: " + leafCert.getSubjectX500Principal());

        } else {
            logger.info("PKITrustManager: Bad cert domain: " + leafCert.getSubjectX500Principal());

            // TODO: fix depth param
            status.addReason(ValidityStatus.BAD_CERT_DOMAIN, leafCert, 0);
        }

        super.checkCertChain(certChain, keyUsage, status);
    }
}
