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
package org.dogtagpki.server.rest;

import javax.ws.rs.POST;
import javax.ws.rs.Path;

import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.system.CertificateSetupRequest;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.apps.PreOpConfig;

/**
 * @author alee
 *
 */
@Path("installer")
public class SystemConfigService extends PKIService {

    public final static Logger logger = LoggerFactory.getLogger(SystemConfigService.class);

    public Configurator configurator;

    public EngineConfig cs;
    public String csType;
    public String csSubsystem;
    public String csState;
    public boolean isMasterCA = false;
    public String instanceRoot;

    public SystemConfigService() throws Exception {

        CMSEngine engine = CMS.getCMSEngine();
        cs = engine.getConfig();

        csType = cs.getType();
        csSubsystem = csType.toLowerCase();
        csState = cs.getState() + "";

        String domainType = cs.getString("securitydomain.select", "existingdomain");
        if (csType.equals("CA") && domainType.equals("new")) {
            isMasterCA = true;
        }

        instanceRoot = cs.getInstanceDir();

        configurator = engine.createConfigurator();
    }

    @POST
    @Path("createRequestID")
    public RequestId createRequestID(CertificateSetupRequest request) throws Exception {

        logger.info("SystemConfigService: Creating request ID");

        try {
            validatePin(request.getPin());
            return configurator.createRequestID();

        } catch (Throwable e) {
            logger.error("Unable to create request ID: " + e.getMessage(), e);
            throw e;
        }
    }

    @POST
    @Path("loadCert")
    public SystemCertData loadCert(CertificateSetupRequest request) throws Exception {

        String tag = request.getTag();
        logger.info("SystemConfigService: Loading existing " + tag + " certificate");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            SystemCertData certData = request.getSystemCert();

            String cert = certData.getCert();
            byte[] binCert = Utils.base64decode(cert);

            String profileID = certData.getProfile();
            String[] dnsNames = certData.getDNSNames();

            String certRequestType = certData.getRequestType();
            String certRequest = certData.getRequest();
            byte[] binCertRequest = Utils.base64decode(certRequest);

            boolean installAdjustValidity = !tag.equals("signing");
            X500Name subjectName = null;

            RequestId requestID = configurator.createRequestID();
            certData.setRequestID(requestID);

            configurator.importCert(
                    binCert,
                    profileID,
                    dnsNames,
                    installAdjustValidity,
                    certRequestType,
                    binCertRequest,
                    subjectName,
                    requestID);

            return certData;

        } catch (PKIException e) { // normal response
            logger.error("Unable to load " + tag + " certificate: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Unable to load " + tag + " certificate: " + e.getMessage(), e);
            throw e;
        }
    }

    @POST
    @Path("setupCert")
    public SystemCertData setupCert(CertificateSetupRequest request) throws Exception {

        String tag = request.getTag();
        logger.info("SystemConfigService: setting up " + tag + " certificate");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            return configurator.setupCert(request);

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @POST
    @Path("initSubsystem")
    public void initSubsystem(CertificateSetupRequest request) throws Exception {

        logger.info("SystemConfigService: Initializing subsystem");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            configurator.initSubsystem();

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @POST
    @Path("setupAdmin")
    public SystemCertData setupAdmin(CertificateSetupRequest request) throws Exception {

        logger.info("SystemConfigService: setting up admin");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            SystemCertData certData = request.getSystemCert();
            configurator.createAdminCertificate(certData);

            return certData;

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    private void validatePin(String pin) throws Exception {

        if (pin == null) {
            throw new BadRequestException("Missing configuration PIN");
        }

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String preopPin = preopConfig.getString("pin");
        if (!preopPin.equals(pin)) {
            throw new BadRequestException("Invalid configuration PIN");
        }
    }
}
