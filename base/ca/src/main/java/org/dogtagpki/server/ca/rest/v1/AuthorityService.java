//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2015 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.ca.rest.v1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.GenericEntity;
import javax.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.rest.base.AuthorityRepository;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.authority.AuthorityResource;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CADisabledException;
import com.netscape.certsrv.ca.CAEnabledException;
import com.netscape.certsrv.ca.CANotLeafException;
import com.netscape.certsrv.ca.CATypeException;
import com.netscape.certsrv.ca.IssuerUnavailableException;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.SubsystemService;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.logging.Auditor;

/**
 * @author ftweedal
 */
public class AuthorityService extends SubsystemService implements AuthorityResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthorityService.class);

    CertificateAuthority hostCA;

    public AuthorityService() {
        CAEngine engine = CAEngine.getInstance();
        hostCA = engine.getCA();
    }

    @Override
    public Response findCAs(String id, String parentID, String dn, String issuerDN) throws Exception {

        logger.info("AuthorityService: Finding CAs");

        CAEngine engine = CAEngine.getInstance();
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        List<AuthorityData> results = authorityRepository.findCAs(id, parentID, dn, issuerDN);

        GenericEntity<List<AuthorityData>> entity =
            new GenericEntity<>(results) {};

        return createOKResponse(entity);
    }

    @Override
    public Response getCA(String aidString) throws Exception {

        logger.info("AuthorityService: Getting CA {}", aidString);

        CAEngine engine = CAEngine.getInstance();
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        AuthorityData authority = authorityRepository.getCA(aidString);

        logger.debug("AuthorityService: - DN: {}", authority.getDN());
        if (authority.getParentID() != null) {
            logger.debug("AuthorityService: - parent ID: {}", authority.getParentID());
        }
        logger.debug("AuthorityService: - issuer DN: {}", authority.getIssuerDN());

        return createOKResponse(authority);
    }

    @Override
    public Response getCert(String aidString) {

        logger.info("AuthorityService: getting cert for authority " + aidString);

        AuthorityID aid = null;
        if (!AuthorityResource.HOST_AUTHORITY.equals(aidString)) {
            try {
                aid = new AuthorityID(aidString);
            } catch (IllegalArgumentException e) {
                throw new BadRequestException("Bad AuthorityID: " + aidString);
            }
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA(aid);

        if (ca == null)
            throw new ResourceNotFoundException("CA \"" + aidString + "\" not found");

        org.mozilla.jss.crypto.X509Certificate cert = ca.getCaX509Cert();
        if (cert == null)
            throw new ResourceNotFoundException(
                "Certificate for CA \"" + aidString + "\" not available");

        try {
            return Response.ok(cert.getEncoded()).build();
        } catch (CertificateEncodingException e) {
            // this really is a 500 Internal Server Error
            throw new PKIException("Error encoding certificate: " + e);
        }
    }

    @Override
    public Response getCertPEM(String aidString) {
        byte[] der = (byte[]) getCert(aidString).getEntity();
        return Response.ok(toPem("CERTIFICATE", der)).build();
    }

    @Override
    public Response getChain(String aidString) {

        logger.info("AuthorityService: getting cert chain for authority " + aidString);

        AuthorityID aid = null;
        if (!AuthorityResource.HOST_AUTHORITY.equals(aidString)) {
            try {
                aid = new AuthorityID(aidString);
            } catch (IllegalArgumentException e) {
                throw new BadRequestException("Bad AuthorityID: " + aidString);
            }
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA(aid);

        if (ca == null)
            throw new ResourceNotFoundException("CA \"" + aidString + "\" not found");

        org.mozilla.jss.netscape.security.x509.CertificateChain chain = ca.getCACertChain();
        if (chain == null)
            throw new ResourceNotFoundException(
                "Certificate chain for CA \"" + aidString + "\" not available");

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            chain.encode(out);
        } catch (IOException e) {
            throw new PKIException("Error encoding certificate chain: " + e);
        }

        return Response.ok(out.toByteArray()).build();
    }

    @Override
    public Response getChainPEM(String aidString) {
        byte[] der = (byte[]) getChain(aidString).getEntity();
        return Response.ok(toPem("PKCS7", der)).build();
    }

    @Override
    public Response createCA(AuthorityData data) {
        CAEngine engine = CAEngine.getInstance();
        AuthorityRepository authorityRepository = engine.getAuthorityRepository();
        data = authorityRepository.createCA(data);
        return createOKResponse(data);
    }

    @Override
    public Response modifyCA(String aidString, AuthorityData data) {

        logger.info("AuthorityService: modifying authority " + aidString);

        AuthorityID aid = null;
        try {
            aid = new AuthorityID(aidString);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Bad AuthorityID: " + aidString);
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA(aid);

        if (ca == null)
            throw new ResourceNotFoundException("CA \"" + aidString + "\" not found");

        Map<String, String> auditParams = new LinkedHashMap<>();
        if (data.getEnabled() != ca.getAuthorityEnabled()) {
            logger.info("AuthorityService:   enabled: " + data.getEnabled());
            auditParams.put("enabled", data.getEnabled().toString());
        }

        String curDesc = ca.getAuthorityDescription();
        String newDesc = data.getDescription();
        if (curDesc != null && !curDesc.equals(newDesc)
                || curDesc == null && newDesc != null) {
            logger.info("AuthorityService:   description: " + data.getDescription());
            auditParams.put("description", data.getDescription());
        }

        try {
            engine.modifyAuthority(ca, data.getEnabled(), data.getDescription());
            audit(ILogger.SUCCESS, OpDef.OP_MODIFY, ca.getAuthorityID().toString(), auditParams);
            return createOKResponse(readAuthorityData(ca));
        } catch (CATypeException e) {
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_MODIFY, ca.getAuthorityID().toString(), auditParams);
            throw new ForbiddenException(e.toString());
        } catch (IssuerUnavailableException e) {
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_MODIFY, ca.getAuthorityID().toString(), auditParams);
            throw new ConflictingOperationException(e.toString());
        } catch (EBaseException e) {
            String message = "Error modifying authority: " + e.getMessage();
            logger.error(message, e);
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_MODIFY, ca.getAuthorityID().toString(), auditParams);
            throw new PKIException(message, e);
        }
    }

    @Override
    public Response enableCA(String aidString) {
        return modifyCA(
            aidString,
            new AuthorityData(null, null, null, null, null, null, true, null, null));
    }

    @Override
    public Response disableCA(String aidString) {
        return modifyCA(
            aidString,
            new AuthorityData(null, null, null, null, null, null, false, null, null));
    }

    @Override
    public Response renewCA(String aidString) {

        logger.info("AuthorityService: renewing cert for authority " + aidString);

        AuthorityID aid = null;
        try {
            aid = new AuthorityID(aidString);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Bad AuthorityID: " + aidString);
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA(aid);

        if (ca == null)
            throw new ResourceNotFoundException("CA \"" + aidString + "\" not found");

        Map<String, String> auditParams = new LinkedHashMap<>();

        try {
            engine.renewAuthority(servletRequest, ca);
            audit(ILogger.SUCCESS, OpDef.OP_MODIFY, aidString, null);
            return createNoContentResponse();
        } catch (CADisabledException e) {
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_MODIFY, aidString, auditParams);
            throw new ConflictingOperationException(e.toString());
        } catch (Exception e) {
            String message = "Error renewing authority: " + e.getMessage();
            logger.error(message, e);
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_MODIFY, aidString, auditParams);
            throw new PKIException(message, e);
        }
    }

    @Override
    public Response deleteCA(String aidString) {

        logger.info("AuthorityService: deleting authority " + aidString);

        AuthorityID aid = null;
        try {
            aid = new AuthorityID(aidString);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Bad AuthorityID: " + aidString);
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA(aid);

        if (ca == null)
            throw new ResourceNotFoundException("CA \"" + aidString + "\" not found");

        Map<String, String> auditParams = new LinkedHashMap<>();

        try {
            engine.deleteAuthority(servletRequest, ca);
            audit(ILogger.SUCCESS, OpDef.OP_DELETE, aidString, null);
            return createNoContentResponse();
        } catch (CATypeException e) {
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_DELETE, aidString, auditParams);
            throw new ForbiddenException(e.toString());
        } catch (CAEnabledException | CANotLeafException e) {
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_DELETE, aidString, auditParams);
            throw new ConflictingOperationException(e.toString());
        } catch (Exception e) {
            String message = "Error modifying authority: " + e.getMessage();
            logger.error(message, e);
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_DELETE, aidString, auditParams);
            throw new PKIException(message, e);
        }
    }

    private static AuthorityData readAuthorityData(CertificateAuthority ca)
            throws PKIException {
        String dn;
        try {
            dn = ca.getX500Name().toLdapDNString();
        } catch (IOException e) {
            throw new PKIException("Error reading CA data: could not determine subject DN");
        }

        String issuerDN;
        BigInteger serial;
        try {
            issuerDN = ca.getCACert().getIssuerName().toString();
            serial = ca.getCACert().getSerialNumber();
        } catch (EBaseException e) {
            throw new PKIException("Error reading CA data: missing CA cert", e);
        }

        AuthorityID parentAID = ca.getAuthorityParentID();
        return new AuthorityData(
            ca.isHostAuthority(),
            dn,
            ca.getAuthorityID().toString(),
            parentAID != null ? parentAID.toString() : null,
            issuerDN,
            serial,
            ca.getAuthorityEnabled(),
            ca.getAuthorityDescription(),
            ca.isReady()
        );
    }

    private String toPem(String name, byte[] data) {
        return "-----BEGIN " + name + "-----\n" +
                Utils.base64encode(data, true) +
                "-----END " + name + "-----\n";
    }

    private void audit(
            String status, String op, String id,
            Map<String, String> params) {

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();
        String msg = CMS.getLogMessage(
                AuditEvent.AUTHORITY_CONFIG,
                auditor.getSubjectID(),
                status,
                auditor.getParamString(ScopeDef.SC_AUTHORITY, op, id, params));
        auditor.log(msg);
    }
}
