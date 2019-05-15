//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.JWS;

/**
 * @author Endi S. Dewata
 */
@Path("acct/{id}")
public class ACMEAccountService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEAccountService.class);

    @Context
    UriInfo uriInfo;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateAccount(@PathParam("id") String accountID, JWS jws) throws Exception {

        logger.info("Updating account " + accountID);

        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        logger.info("Header: " + protectedHeader);
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        ACMEEngine engine = ACMEEngine.getInstance();
        engine.validateNonce(header.getNonce());

        URI kid = header.getKid();
        String kidPath = kid.getPath();
        String jwsAccountID = kidPath.substring(kidPath.lastIndexOf('/') + 1);

        if (!accountID.equals(jwsAccountID)) {
            throw new Exception("Invalid KID: " + kid);
        }

        String payload = new String(jws.getPayloadAsBytes(), "UTF-8");
        logger.info("Payload: " + payload);

        ACMEAccount update = ACMEAccount.fromJSON(payload);

        ACMEAccount account = engine.getAccount(accountID);
        engine.validateJWS(jws, header.getAlg(), account.getJWK());

        if (!"valid".equals(account.getStatus())) {
            throw new Exception("Invalid account: " + accountID);
        }

        account.setStatus(update.getStatus());
        account.setContact(update.getContact());

        ResponseBuilder builder = Response.ok(account);

        ACMENonce nonce = engine.createNonce();
        builder.header("Replay-Nonce", nonce.getValue());

        URI directoryURL = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(directoryURL, "index");

        builder.entity(account);

        return builder.build();
    }
}
