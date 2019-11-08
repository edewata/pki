//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.database;

import java.net.URI;
import java.util.Date;

import org.bson.Document;
import org.bson.conversions.Bson;
import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.JWK;

import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.model.Filters;

/**
 * @author Endi S. Dewata
 */
public class MongoDatabase extends ACMEDatabase {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(MongoDatabase.class);

    protected MongoClientURI uri;
    protected MongoClient mongoClient;
    protected com.mongodb.client.MongoDatabase mongoDatabase;

    public void init() throws Exception {

        logger.info("Parameters:");
        for (String name : config.getParameterNames()) {
            logger.info("- " + name + ": " + config.getParameter(name));
        }

        String url = config.getParameter("url");

        if (url == null) {
            String hostname = config.getParameter("hostname");
            String database = config.getParameter("database");
            url = "mongodb+srv://" + hostname + "/" + database;
        }

        uri = new MongoClientURI(url);
        logger.info("Connecting to " + uri);

        try {
            mongoClient = new MongoClient(uri);
            mongoDatabase = mongoClient.getDatabase(uri.getDatabase());

            logger.info("Collections:");
            for (String name : mongoDatabase.listCollectionNames()) {
                logger.info(" - " + name);
            }

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }

    public void close() throws Exception {
        mongoClient.close();
    }

    public void addNonce(ACMENonce nonce) throws Exception {

        String json = nonce.toJSON();
        logger.info("Adding ACME nonce: " + json);

        try {
            MongoCollection<Document> nonces = mongoDatabase.getCollection("nonces");

            Document document = Document.parse(json);
            logger.info("Mongo nonce: " + document.toJson());

            nonces.insertOne(document);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }

    public ACMENonce removeNonce(String value) throws Exception {

        logger.info("Removing ACME nonce: " + value);

        try {
            MongoCollection<Document> nonces = mongoDatabase.getCollection("nonces");

            Bson query = Filters.eq("value", value);
            FindIterable<Document> documents = nonces.find(query);

            MongoCursor<Document> cursor = documents.iterator();
            if (!cursor.hasNext()) {
                logger.info("Nonce not found: " + value);
                return null;
            }

            Document document = cursor.next();

            String json = document.toJson();
            logger.info("Mongo nonce: " + json);

            ACMENonce nonce = new ACMENonce();
            nonce.setValue(value);

            Long expirationTime = document.getLong("expirationTime");
            nonce.setExpirationTime(new Date(expirationTime));

            logger.info("ACME nonce: " + nonce.toJSON());

            nonces.deleteOne(query);

            return nonce;

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }

    public void removeExpiredNonces(Date currentTime) throws Exception {

        logger.info("Removing ACME nonces: " + currentTime);

        try {
            MongoCollection<Document> nonces = mongoDatabase.getCollection("nonces");

            Bson query = Filters.lte("expirationTime", currentTime);
            FindIterable<Document> documents = nonces.find(query);

            MongoCursor<Document> cursor = documents.iterator();
            while (cursor.hasNext()) {

                Document document = cursor.next();
                String json = document.toJson();
                logger.info("Mongo nonce: " + json);

                ACMENonce nonce = ACMENonce.fromJSON(json);
                logger.info("ACME nonce: " + nonce.toJSON());

                nonces.deleteOne(query);
            }

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }

    public ACMEAccount getAccount(String accountID) throws Exception {

        try {
            MongoCollection<Document> accounts = mongoDatabase.getCollection("accounts");

            Bson query = Filters.eq("accountID", accountID);
            FindIterable<Document> documents = accounts.find(query);

            MongoCursor<Document> cursor = documents.iterator();
            if (!cursor.hasNext()) {
                return null;
            }

            Document document = cursor.next();
            String json = document.toJson();
            logger.info("Mongo account: " + json);

            ACMEAccount account = ACMEAccount.fromJSON(json);
            account.setID(accountID);

            Document jwk = document.get("jwk", Document.class);
            account.setJWK(JWK.fromJSON(jwk.toJson()));

            logger.info("ACME account: " + account.toJSON());

            return account;

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }

    public void addAccount(ACMEAccount account) throws Exception {

        String json = account.toJSON();
        logger.info("Adding ACME account: " + json);

        try {
            MongoCollection<Document> accounts = mongoDatabase.getCollection("accounts");

            Document document = Document.parse(json);
            document.put("accountID", account.getID());

            String jwkJSON = account.getJWK().toJSON();
            document.put("jwk", Document.parse(jwkJSON));

            logger.info("Mongo account: " + document.toJson());

            accounts.insertOne(document);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }

    public ACMEOrder getOrder(String orderID) throws Exception {

        try {
            MongoCollection<Document> accounts = mongoDatabase.getCollection("orders");

            Bson query = Filters.eq("orderID", orderID);
            FindIterable<Document> documents = accounts.find(query);

            MongoCursor<Document> cursor = documents.iterator();
            if (!cursor.hasNext()) {
                return null;
            }

            Document document = cursor.next();
            String accountID = document.getString("accountID");
            String json = document.toJson();
            logger.info("Mongo order: " + json);

            ACMEOrder order = ACMEOrder.fromJSON(json);
            order.setID(orderID);
            order.setAccountID(accountID);
            logger.info("ACME order: " + order.toJSON());

            return order;

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }

    public ACMEOrder getOrderByAuthorization(URI authzURI) throws Exception {

        try {
            MongoCollection<Document> orders = mongoDatabase.getCollection("orders");

            FindIterable<Document> documents = orders.find();

            MongoCursor<Document> cursor = documents.iterator();
            while (cursor.hasNext()) {

                Document document = cursor.next();
                String orderID = document.getString("orderID");
                String accountID = document.getString("accountID");
                String json = document.toJson();
                logger.info("Mongo order: " + json);

                ACMEOrder order = ACMEOrder.fromJSON(json);
                order.setID(orderID);
                order.setAccountID(accountID);
                logger.info("ACME order: " + order.toJSON());

                if (order.getAuthorizations() == null) {
                    continue;
                }

                for (URI authorization : order.getAuthorizations()) {
                    if (!authorization.equals(authzURI)) continue;

                    return order;
                }
            }

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }

        return null;
    }

    public void addOrder(ACMEOrder order) throws Exception {

        String json = order.toJSON();
        logger.info("Adding ACME order: " + json);

        try {
            MongoCollection<Document> orders = mongoDatabase.getCollection("orders");

            Document document = Document.parse(json);
            document.put("orderID", order.getID());
            document.put("accountID", order.getAccountID());
            logger.info("Mongo order: " + document.toJson());

            orders.insertOne(document);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }

    public void updateOrder(ACMEOrder order) throws Exception {

        String json = order.toJSON();
        logger.info("Updating ACME order: " + json);

        try {
            MongoCollection<Document> orders = mongoDatabase.getCollection("orders");

            Bson query = Filters.eq("orderID", order.getID());

            Document document = Document.parse(json);
            document.put("orderID", order.getID());
            document.put("accountID", order.getAccountID());
            logger.info("Mongo order: " + document.toJson());

            orders.replaceOne(query, document);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }

    public ACMEAuthorization getAuthorization(String authzID) throws Exception {

        try {
            MongoCollection<Document> authorizations = mongoDatabase.getCollection("authorizations");

            Bson query = Filters.eq("authzID", authzID);
            FindIterable<Document> documents = authorizations.find(query);

            MongoCursor<Document> cursor = documents.iterator();
            if (!cursor.hasNext()) {
                return null;
            }

            Document document = cursor.next();
            String accountID = document.getString("accountID");
            String json = document.toJson();
            logger.info("Mongo authorization: " + json);

            ACMEAuthorization authorization = ACMEAuthorization.fromJSON(json);
            authorization.setID(authzID);
            authorization.setAccountID(accountID);
            logger.info("ACME authorization: " + authorization.toJSON());

            return authorization;

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }

    public ACMEAuthorization getAuthorizationByChallenge(URI challengeURI) throws Exception {

        try {
            MongoCollection<Document> authorizations = mongoDatabase.getCollection("authorizations");

            FindIterable<Document> documents = authorizations.find();

            MongoCursor<Document> cursor = documents.iterator();
            while (cursor.hasNext()) {

                Document document = cursor.next();
                String authzID = document.getString("authzID");
                String accountID = document.getString("accountID");
                String json = document.toJson();
                logger.info("Mongo authorization: " + json);

                ACMEAuthorization authorization = ACMEAuthorization.fromJSON(json);
                authorization.setID(authzID);
                authorization.setAccountID(accountID);
                logger.info("ACME authorization: " + authorization.toJSON());

                if (authorization.getChallenges() == null) {
                    continue;
                }

                for (ACMEChallenge challenge : authorization.getChallenges()) {
                    URI url = challenge.getURL();
                    if (!url.equals(challengeURI)) continue;

                    return authorization;
                }
            }

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }

        return null;
    }

    public void addAuthorization(ACMEAuthorization authorization) throws Exception {

        String json = authorization.toJSON();
        logger.info("Adding ACME authorization: " + json);

        try {
            MongoCollection<Document> authorizations = mongoDatabase.getCollection("authorizations");

            Document document = Document.parse(json);
            document.put("authzID", authorization.getID());
            document.put("accountID", authorization.getAccountID());
            logger.info("Mongo authorization: " + document.toJson());

            authorizations.insertOne(document);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }

    public void updateAuthorization(ACMEAuthorization authorization) throws Exception {

        String json = authorization.toJSON();
        logger.info("Updating ACME authorization: " + json);

        try {
            MongoCollection<Document> authorizations = mongoDatabase.getCollection("authorizations");

            Bson query = Filters.eq("authzID", authorization.getID());

            Document document = Document.parse(json);
            document.put("authzID", authorization.getID());
            document.put("accountID", authorization.getAccountID());
            logger.info("Mongo authorization: " + document.toJson());

            authorizations.replaceOne(query, document);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }
}
