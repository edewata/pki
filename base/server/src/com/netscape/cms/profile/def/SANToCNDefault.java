//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.profile.def;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Locale;

import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.DNSName;
import org.mozilla.jss.netscape.security.x509.GeneralName;
import org.mozilla.jss.netscape.security.x509.GeneralNameInterface;
import org.mozilla.jss.netscape.security.x509.GeneralNames;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectAlternativeNameExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This plug-in replaces the subject DN with CN=<DNS name>
 * using the first DNS name in the SAN extension.
 *
 * @author Endi S. Dewata
 */
public class SANToCNDefault extends EnrollExtDefault {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SANToCNDefault.class);

    private static final String LOG_PREFIX = "SANtoCNDefault: ";

    public void populate(IRequest request, X509CertInfo info) throws EProfileException {

        logger.info(LOG_PREFIX + "Checking SAN extension");

        SubjectAlternativeNameExtension san = (SubjectAlternativeNameExtension)
            getExtension(PKIXExtensions.SubjectAlternativeName_Id.toString(), info);

        if (san == null) {
            String message = "Unable to find SAN extension";
            logger.error(LOG_PREFIX + message);
            throw new EProfileException(message);
        }

        String dnsName = null;

        GeneralNames generalNames = san.getGeneralNames();
        for (GeneralNameInterface generalName : generalNames) {

            if (generalName instanceof GeneralName) {
                generalName = ((GeneralName) generalName).unwrap();
            }

            if (generalName instanceof DNSName) {
                dnsName = ((DNSName) generalName).getValue();
                break;
            }
        }

        if (dnsName == null) {
            String message = "Unable to find DNS name in SAN extension";
            logger.error(LOG_PREFIX + message);
            throw new EProfileException(message);
        }

        logger.info(LOG_PREFIX + "DNS name: " + dnsName);

        try {
            X500Name subjectDN = new X500Name("CN=" + dnsName);
            logger.info(LOG_PREFIX + "Setting Subject DN to " + subjectDN);

            CertificateSubjectName subjectName = new CertificateSubjectName(subjectDN);
            info.set(X509CertInfo.SUBJECT, subjectName);

        } catch (CertificateException | IOException e) {
            String message = "Unable to set Subject DN: " + e.getMessage();
            logger.error(LOG_PREFIX + message, e);
            throw new EProfileException(message, e);
        }
    }

    public String getText(Locale locale) {
        return "This default constructs a Subject DN from the first DNS name in "
            + "Subject Alternative Name extension.";
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    public String getValue(String name, Locale locale, X509CertInfo info) {
        return null;
    }

    public void setValue(String name, Locale locale, X509CertInfo info, String value) {
    }
}
