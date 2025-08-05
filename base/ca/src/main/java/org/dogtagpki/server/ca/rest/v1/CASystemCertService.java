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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.ca.rest.v1;

import java.security.cert.X509Certificate;

import javax.ws.rs.core.Response;

import org.dogtagpki.ca.CASystemCertResource;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.CASigningUnit;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.cms.servlet.admin.KRAConnectorProcessor;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author alee
 */
public class CASystemCertService extends PKIService implements CASystemCertResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CASystemCertService.class);

    @Override
    public Response getSigningCert() throws Exception {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        CASigningUnit su = ca.getSigningUnit();

        X509Certificate signingCert = su.getCert();
        X509CertImpl cert = new X509CertImpl(signingCert.getEncoded());
        java.security.cert.X509Certificate[] certChain = engine.getCertChain(cert);

        PKCS7 pkcs7 = new PKCS7(new AlgorithmId[0],
                new ContentInfo(new byte[0]),
                certChain,
                new SignerInfo[0]);

        CertData certData = CertData.fromCertChain(pkcs7);

        return sendConditionalGetResponse(DEFAULT_LONG_CACHE_LIFETIME, certData, request);
    }

    @Override
    public Response getTransportCert() throws Exception {

        logger.info("CASystemCertService: Getting transport cert");

        CAEngine engine = CAEngine.getInstance();

        KRAConnectorProcessor processor = new KRAConnectorProcessor(getLocale(headers));
        processor.setCMSEngine(engine);
        processor.init();

        KRAConnectorInfo info = processor.getConnectorInfo();

        String encodedCert = info.getTransportCert();
        logger.info("CASystemCertService: transport cert: " + encodedCert);

        X509Certificate cert;
        if (encodedCert != null) {
            byte[] bytes = Utils.base64decode(encodedCert);
            cert = new X509CertImpl(bytes);
        } else {
            String nickname = info.getTransportCertNickname();
            logger.info("CASystemCertService: transport cert nickname: " + nickname);

            CryptoManager manager = CryptoManager.getInstance();
            cert = manager.findCertByNickname(nickname);
            cert = new X509CertImpl(cert.getEncoded());
        }

        logger.info("CASystemCertService: Generating cert chain");
        java.security.cert.X509Certificate[] certChain = engine.getCertChain(cert);

        PKCS7 pkcs7 = new PKCS7(new AlgorithmId[0],
                new ContentInfo(new byte[0]),
                certChain,
                new SignerInfo[0]);

        CertData certData = CertData.fromCertChain(pkcs7);

        return sendConditionalGetResponse(DEFAULT_LONG_CACHE_LIFETIME, certData, request);
    }
}
