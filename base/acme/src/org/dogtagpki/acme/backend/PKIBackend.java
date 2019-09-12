//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.backend;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;
import org.dogtagpki.acme.ACMERevocation;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.cert.CertRevokeRequest;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Endi S. Dewata
 */
public class PKIBackend extends ACMEBackend {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIBackend.class);

    private String url;
    private String profile;
    private String nickname;
    private String username;
    private String password;

    public String getURL() {
        return url;
    }

    public void setURL(String url) {
        this.url = url;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void init() {
        url = config.getParameter("url");
        profile = config.getParameter("profile");
        nickname = config.getParameter("nickname");
        username = config.getParameter("username");
        password = config.getParameter("password");
    }

    public String issueCertificate(String csr) throws Exception {

        logger.info("Issuing certificate");

        logger.info("PKI server: " + url);
        logger.info("- profile: " + profile);
        if (nickname != null) {
            logger.info("- nickname: " + nickname);
        }
        if (username != null) {
            logger.info("- username: " + username);
        }

        AuthorityID aid = null;
        X500Name adn = null;

        ClientConfig clientConfig = new ClientConfig();
        clientConfig.setServerURL(url);
        clientConfig.setCertNickname(nickname);
        clientConfig.setUsername(username);
        clientConfig.setPassword(password);

        PKIClient pkiClient = new PKIClient(clientConfig);
        CAClient caClient = new CAClient(pkiClient);
        CACertClient certClient = new CACertClient(caClient);
        CertEnrollmentRequest certEnrollmentRequest = certClient.getEnrollmentTemplate(profile);

        for (ProfileInput input : certEnrollmentRequest.getInputs()) {

            ProfileAttribute typeAttr = input.getAttribute("cert_request_type");
            if (typeAttr != null) {
                typeAttr.setValue("pkcs10");
            }

            ProfileAttribute csrAttr = input.getAttribute("cert_request");
            if (csrAttr != null) {
                csrAttr.setValue(csr);
            }
        }

        logger.info("Request:\n" + certEnrollmentRequest);

        CertRequestInfos infos = certClient.enrollRequest(certEnrollmentRequest, aid, adn);

        logger.info("Responses:");
        CertRequestInfo info = infos.getEntries().iterator().next();

        RequestId requestId = info.getRequestId();

        logger.info(" - Request ID: " + requestId);
        logger.info("   Type: " + info.getRequestType());
        logger.info("   Request Status: " + info.getRequestStatus());
        logger.info("   Operation Result: " + info.getOperationResult());

        String error = info.getErrorMessage();
        if (error != null) {
            throw new Exception("Unable to generate certificate: " + error);
        }

        CertReviewResponse reviewInfo = certClient.reviewRequest(requestId);
        certClient.approveRequest(requestId, reviewInfo);

        info = certClient.getRequest(requestId);
        logger.info("Serial number: " + info.getCertId().toHexString());

        CertId id = info.getCertId();

        return Base64.encodeBase64URLSafeString(id.toBigInteger().toByteArray());
    }

    public String getCertificateChain(String certID) throws Exception {

        CertId id = new CertId(new BigInteger(1, Base64.decodeBase64(certID)));
        logger.info("Serial number: " + id.toHexString());

        logger.info("PKI server: " + url);
        if (nickname != null) {
            logger.info("- nickname: " + nickname);
        }
        if (username != null) {
            logger.info("- username: " + username);
        }

        ClientConfig clientConfig = new ClientConfig();
        clientConfig.setServerURL(url);
        clientConfig.setCertNickname(nickname);
        clientConfig.setUsername(username);
        clientConfig.setPassword(password);

        PKIClient pkiClient = new PKIClient(clientConfig);
        CAClient caClient = new CAClient(pkiClient);
        CACertClient certClient = new CACertClient(caClient);

        CertData certData = certClient.getCert(id);

        String pkcs7Chain = certData.getPkcs7CertChain();
        logger.info("Cert chain:\n" + pkcs7Chain);

        PKCS7 pkcs7 = new PKCS7(Utils.base64decode(pkcs7Chain));
        X509Certificate[] certs = pkcs7.getCertificates();

        if (certs == null || certs.length == 0) {
            throw new Error("PKCS #7 data contains no certificates");
        }

        // sort certs from leaf to root
        certs = CryptoUtil.sortCertificateChain(certs, true);

        StringWriter sw = new StringWriter();

        try (PrintWriter out = new PrintWriter(sw, true)) {
            for (X509Certificate cert : certs) {
                out.println(Cert.HEADER);
                out.print(Utils.base64encode(cert.getEncoded(), true));
                out.println(Cert.FOOTER);
            }
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

        X509CertImpl certImpl = new X509CertImpl(certBytes);
        CertId certID = new CertId(certImpl.getSerialNumber());
        logger.info("Serial number: " + certID.toHexString());

        logger.info("PKI server: " + url);
        if (nickname != null) {
            logger.info("- nickname: " + nickname);
        }
        if (username != null) {
            logger.info("- username: " + username);
        }

        ClientConfig clientConfig = new ClientConfig();
        clientConfig.setServerURL(url);
        clientConfig.setCertNickname(nickname);
        clientConfig.setUsername(username);
        clientConfig.setPassword(password);

        PKIClient pkiClient = new PKIClient(clientConfig);
        CAClient caClient = new CAClient(pkiClient);
        CACertClient certClient = new CACertClient(caClient);

        logger.info("Reviewing certificate");
        CertData certData = certClient.reviewCert(certID);

        CertRevokeRequest request = new CertRevokeRequest();
        request.setReason(RevocationReason.valueOf(reason));
        request.setNonce(certData.getNonce());

        logger.info("Revoking certificate");
        CertRequestInfo certRequestInfo = certClient.revokeCert(certID, request);

        RequestStatus status = certRequestInfo.getRequestStatus();
        if (status != RequestStatus.COMPLETE) {
            throw new Exception("Unable to revoke certificate: " + status);
        }

        if (certRequestInfo.getOperationResult().equals(CertRequestInfo.RES_ERROR)) {
            String error = certRequestInfo.getErrorMessage();
            throw new Exception("Unable to revoke certificate: " + error);
        }
    }
}
