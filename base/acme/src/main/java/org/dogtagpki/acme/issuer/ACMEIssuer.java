//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.issuer;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.NotImplementedException;
import org.dogtagpki.acme.ACMEError;
import org.dogtagpki.acme.ACMEException;
import org.dogtagpki.acme.ACMERevocation;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;

/**
 * @author Endi S. Dewata
 */
public class ACMEIssuer {

    protected ACMEIssuerConfig config;

    public ACMEIssuerConfig getConfig() {
        return config;
    }

    public void setConfig(ACMEIssuerConfig config) {
        this.config = config;
    }

    public void init() throws Exception {
    }

    public void close() throws Exception {
    }

    /**
     * This method generates a unique ID for a certificate.
     *
     * By default this method will return the base64-encoded serial number
     * of the certificate. This method may be overridden to generate a issuer-
     * specific unique ID for the certificate.
     *
     * @param cert Certificate.
     * @return Unique ID for the certificate.
     * @throws Exception
     */
    public String getCertificateID(X509Certificate cert) throws Exception {
        BigInteger serialNumber = cert.getSerialNumber();
        return Base64.encodeBase64URLSafeString(serialNumber.toByteArray());
    }

    /**
     * This method generates a certificate using the provided certificate signing request,
     * then returns the new certificate.
     *
     * @param pkcs10 PKCS #10 certificate signing request.
     * @return Certificate.
     * @throws Exception
     */
    public X509Certificate generateCertificate(PKCS10 pkcs10) throws Exception {
        throw new NotImplementedException("ACMEIssuer.generateCertificate() must be overridden by specific implementation");
    }

    /**
     * This method generates a certificate using the provided certificate signing request,
     * then returns a unique ID for the new certificate.
     *
     * @param pkcs10 PKCS #10 certificate signing request.
     * @return Unique ID for the new certificate.
     * @throws Exception
     */
    public String issueCertificate(PKCS10 pkcs10) throws Exception {
        X509Certificate cert = generateCertificate(pkcs10);
        return getCertificateID(cert);
    }

    public String getCertificateChain(String certID) throws Exception {
        throw new NotImplementedException("ACMEIssuer.getCertificateChain() must be overridden by specific implementation");
    }

    /**
     * Revoke the certificate.
     *
     * This will be invoked after the ACMEEngine has performed revocation
     * authorisation checks; i.e. either the request was signed by the
     * certificate key, or it was signed by an account key and that account
     * has authorisations for all identifiers in the certificate.
     *
     * The engine DOES NOT cryptographically verify the certificate, nor
     * does it check that the certificate actually came from the ACME
     * issuer.
     *
     * Therefore ACMEIssuer implementations before revoking a cert MUST check
     * that the certificate to be revoked really was issued by the ACME issuer
     * and has not been tampered with.  Otherwise, a client could present a
     * certificate from a different issuer or an altered certificate, causing
     * an arbitrary (or targeted) certificate to be revoked.
     *
     */
    public void revokeCertificate(ACMERevocation revocation) throws Exception {


        ACMEError error = new ACMEError();
        error.setType("urn:ietf:params:acme:error:unsupported");
        error.setDetail("Certificate revocation not supported");

        throw new ACMEException(HttpServletResponse.SC_NOT_IMPLEMENTED, error);
    }
}
