//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;
import java.util.Date;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEError;
import org.dogtagpki.acme.ACMEHeader;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.JWS;
import org.dogtagpki.acme.issuer.ACMEIssuer;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Utils;

/**
 * @author Endi S. Dewata
 */
@Path("order/{id}/finalize")
@ACMEManagedService
public class ACMEFinalizeOrderService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEFinalizeOrderService.class);

    @Context
    UriInfo uriInfo;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response handlePOST(@PathParam("id") String orderID, JWS jws) throws Exception {

        logger.info("Finalizing order " + orderID);

        String protectedHeader = new String(jws.getProtectedHeaderAsBytes(), "UTF-8");
        logger.info("Header: " + protectedHeader);
        ACMEHeader header = ACMEHeader.fromJSON(protectedHeader);

        ACMEEngine engine = ACMEEngine.getInstance();
        engine.validateNonce(header.getNonce());

        URI kid = header.getKid();
        String kidPath = kid.getPath();
        String accountID = kidPath.substring(kidPath.lastIndexOf('/') + 1);
        logger.info("Account ID: " + accountID);

        ACMEAccount account = engine.getAccount(accountID);
        engine.validateJWS(jws, header.getAlg(), account.getJWK());

        String payload = new String(jws.getPayloadAsBytes(), "UTF-8");
        logger.info("Payload: " + payload);

        ACMEOrder order = engine.getOrder(account, orderID);

        String orderStatus = order.getStatus();
        logger.info("Order status: " + orderStatus);

        if (!orderStatus.equals("pending")) {
            // return current order without additional processing
            return buildResponse(order);
        }

        // here the order is officially "pending", but it could actually be
        // "pending", "ready", or "invalid" depending on the authz status

        orderStatus = "ready";

        logger.info("Authorizations:");
        for (String orderAuthzID : order.getAuthzIDs()) {
            ACMEAuthorization authz = engine.getAuthorization(account, orderAuthzID);
            String authzStatus = authz.getStatus();
            logger.info("- " + orderAuthzID + ": " + authzStatus);

            if (authzStatus.equals("pending")) {
                // if any of the authz is pending, the order is pending too
                orderStatus = "pending";
                break;

            } else if (!authzStatus.equals("valid")) {
                // if any of the authz is not valid, the order is invalid
                orderStatus = "invalid";
                break;
            }

            // if the authz is valid, the order might be valid too,
            // but continue checking other authzs for the order
        }

        if (orderStatus.equals("invalid")) {
            // RFC 8555 Section 7.1.6: Status Changes
            //
            // The order also moves to the "invalid" state if it expires or one of
            // its authorizations enters a final state other than "valid" ("expired",
            // "revoked", or "deactivated").

            logger.info("Order " + order.getID() + " is invalid");
            order.setStatus(orderStatus);

            Date orderExpirationTime = engine.getPolicy().getInvalidOrderExpirationTime(new Date());
            order.setExpirationTime(orderExpirationTime);

            engine.updateOrder(account, order);

            // TODO: generate proper exception
            throw new Exception("Order not authorized: " + orderID);

        } else if (orderStatus.equals("pending")) {
            // RFC 8555 Section 7.4: Applying for Certificate Issuance
            //
            // A request to finalize an order will result in error if the order is
            // not in the "ready" state.  In such cases, the server MUST return a
            // 403 (Forbidden) error with a problem document of type
            // "orderNotReady".  The client should then send a POST-as-GET request
            // to the order resource to obtain its current state.  The status of the
            // order will indicate what action the client should take (see below).

            ResponseBuilder builder = Response.status(Response.Status.FORBIDDEN);
            builder.type("application/problem+json");

            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:orderNotReady");
            error.setDetail("Order not ready: " + orderID);
            builder.entity(error);

            throw new WebApplicationException(builder.build());
        }

        // here the order is officially "ready"

        logger.info("Order " + order.getID() + " is ready");
        order.setStatus("ready");

        Date orderExpirationTime = engine.getPolicy().getReadyOrderExpirationTime(new Date());
        order.setExpirationTime(orderExpirationTime);

        engine.updateOrder(account, order);

        // The following code will process the order immediately which could
        // take some time. To improve the response time of this API the order
        // processing can be done asynchronously in a separate thread. This
        // may require storing the CSR in the order record so that it can be
        // picked up by the order processing thread.

        logger.info("Processing order " + order.getID());
        order.setStatus("processing");

        Date processingOrderExpirationTime = engine.getPolicy().getProcessingOrderExpirationTime(new Date());
        order.setExpirationTime(processingOrderExpirationTime);

        engine.updateOrder(account, order);

        ACMEOrder request = ACMEOrder.fromJSON(payload);

        String csr = request.getCSR();
        logger.info("CSR: " + csr);

        byte[] csrBytes = Utils.base64decode(csr);
        PKCS10 pkcs10 = new PKCS10(csrBytes);

        engine.validateCSR(account, order, pkcs10);

        ACMEIssuer issuer = engine.getIssuer();
        String certID = issuer.issueCertificate(pkcs10);
        logger.info("Certificate issued: " + certID);

        order.setCertID(certID);

        // RFC 8555 Section 7.1.3: Order Objects
        //
        // expires (optional, string):  The timestamp after which the server
        //    will consider this order invalid, encoded in the format specified
        //    in [RFC3339].  This field is REQUIRED for objects with "pending"
        //    or "valid" in the status field.

        logger.info("Order " + order.getID() + " is valid");
        order.setStatus("valid");

        Date validOrderExpirationTime = engine.getPolicy().getValidOrderExpirationTime(new Date());
        order.setExpirationTime(validOrderExpirationTime);

        engine.updateOrder(account, order);

        return buildResponse(order);
    }

    public Response buildResponse(ACMEOrder order) throws Exception {

        ACMEEngine engine = ACMEEngine.getInstance();
        String orderID = order.getID();
        String certID = order.getCertID();

        URI finalizeURL = uriInfo.getBaseUriBuilder().path("order").path(orderID).path("finalize").build();
        order.setFinalize(finalizeURL);

        URI certURL = uriInfo.getBaseUriBuilder().path("cert").path(certID).build();
        order.setCertificate(certURL);

        ResponseBuilder builder = Response.ok();

        ACMENonce nonce = engine.createNonce();
        builder.header("Replay-Nonce", nonce.getID());

        /* This is not required by ACME protocol but mod_md has a
         * bug[1] causing it to fail if there is no Location header
         * in the response.  So we add it.  This is also what
         * boulder / Let's Encrypt do.
         *
         * [1] https://github.com/icing/mod_md/issues/216
         */
        URI orderURL = uriInfo.getBaseUriBuilder().path("order").path(orderID).build();
        builder.location(orderURL);

        URI indexURL = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(indexURL, "index");

        builder.entity(order);

        return builder.build();
    }
}
