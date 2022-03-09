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
package org.dogtagpki.server.ca;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Date;

import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attribute;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attributes;
import org.mozilla.jss.netscape.security.pkcs.PKCS9Attribute;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.ca.CASigningUnit;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.servlet.csadmin.BootstrapProfile;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class CAConfigurator extends Configurator {

    public CAConfigurator(CMSEngine engine) {
        super(engine);
    }

    public RequestId createRequestID() throws Exception {
        CAEngine engine = CAEngine.getInstance();
        CertRequestRepository requestRepository = engine.getCertRequestRepository();
        return requestRepository.createRequestID();
    }

    public CertId createCertID() throws Exception {
        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certificateRepository = engine.getCertificateRepository();
        BigInteger serialNumber = certificateRepository.getNextSerialNumber();
        return new CertId(serialNumber);
    }

    public void updateRequestRecord(
            Request request,
            X509CertImpl cert) throws Exception {

        logger.info("CAConfigurator: Updating request record " + request.getRequestId().toHexString());
        logger.info("CAConfigurator: - cert serial number: 0x" + cert.getSerialNumber().toString(16));

        CAEngine engine = CAEngine.getInstance();
        RequestRepository repository = engine.getRequestRepository();

        request.setExtData(EnrollProfile.REQUEST_CERTINFO, cert.getInfo());
        request.setExtData(EnrollProfile.REQUEST_ISSUED_CERT, cert);

        request.setRequestStatus(RequestStatus.COMPLETE);

        repository.updateRequest(request);
    }

    public void createCertRecord(X509CertImpl cert, RequestId requestID, String profileID) throws Exception {

        logger.info("CAConfigurator: Creating cert record 0x" + cert.getSerialNumber().toString(16));
        logger.info("CAConfigurator: - subject: " + cert.getSubjectDN());
        logger.info("CAConfigurator: - issuer: " + cert.getIssuerDN());

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certificateRepository = engine.getCertificateRepository();

        CertRecord certRecord = certificateRepository.createCertRecord(
                requestID,
                profileID,
                cert);

        certificateRepository.addCertificateRecord(certRecord);
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

    @Override
    public void importRequest(
            RequestId requestID,
            String profileID,
            String[] dnsNames,
            boolean installAdjustValidity,
            String certRequestType,
            byte[] binCertRequest) throws Exception {

        logger.info("CAConfigurator: Importing " + certRequestType + " request");
    }

    @Override
    public X509CertImpl createCert(
            RequestId requestID,
            String keyAlgorithm,
            X509Key x509key,
            String profileID,
            PrivateKey signingPrivateKey,
            String signingAlgorithm,
            String certRequestType,
            byte[] binCertRequest,
            X500Name issuerName,
            X500Name subjectName) throws Exception {

        logger.info("CAConfigurator: Loading request record " + requestID.toHexString());

        CAEngine engine = CAEngine.getInstance();
        CertRequestRepository requestRepository = engine.getCertRequestRepository();
        Request request = requestRepository.readRequest(requestID);

        CertId certID = createCertID();
        logger.info("CAConfigurator: Creating cert " + certID.toHexString());

        logger.info("CAConfigurator: - subject: " + subjectName);

        if (issuerName == null) { // local (not selfsign) cert

            CAEngineConfig engineConfig = engine.getConfig();
            CAConfig caConfig = engineConfig.getCAConfig();
            IConfigStore caSigningCfg = caConfig.getSubStore("signing");

            // create CA signing unit
            CASigningUnit signingUnit = new CASigningUnit();
            signingUnit.init(caSigningCfg, null);

            X509CertImpl caCertImpl = signingUnit.getCertImpl();
            CertificateSubjectName certSubjectName = caCertImpl.getSubjectObj();

            // use CA's issuer object to preserve DN encoding
            issuerName = (X500Name) certSubjectName.get(CertificateIssuerName.DN_NAME);
            signingPrivateKey = signingUnit.getPrivateKey();
        }

        CertificateIssuerName certIssuerName = new CertificateIssuerName(issuerName);
        logger.info("CAConfigurator: - issuer: " + certIssuerName);

        CertificateExtensions extensions = new CertificateExtensions();

        String instanceRoot = cs.getInstanceDir();
        String configurationRoot = cs.getString("configurationRoot");
        String profilePath = instanceRoot + configurationRoot + profileID;

        logger.info("CAConfigurator: Loading " + profilePath);
        IConfigStore profileConfig = engine.createFileConfigStore(profilePath);
        BootstrapProfile profile = new BootstrapProfile(profileConfig);

        Date date = new Date();
        X509CertInfo info = CryptoUtil.createX509CertInfo(
                x509key,
                certID.toBigInteger(),
                certIssuerName,
                subjectName,
                date,
                date,
                keyAlgorithm,
                extensions);

        profile.populate(request, info);

        X509CertImpl cert = CryptoUtil.signCert(signingPrivateKey, info, signingAlgorithm);
        logger.info("CAConfigurator: Cert info:\n" + info);

        createCertRecord(
                cert,
                request.getRequestId(),
                profileConfig.getString("profileIDMapping"));

        updateRequestRecord(request, cert);

        return cert;
    }

    @Override
    public void initSubsystem() throws Exception {

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig engineConfig = engine.getConfig();

        CertificateAuthority ca = engine.getCA();
        ca.setConfig(engineConfig.getCAConfig());
        ca.initCertSigningUnit();
    }
}
