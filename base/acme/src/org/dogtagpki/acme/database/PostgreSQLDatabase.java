//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.database;

import java.net.URI;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEIdentifier;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.JWK;

/**
 * @author Endi S. Dewata
 */
public class PostgreSQLDatabase extends ACMEDatabase {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PostgreSQLDatabase.class);

    protected Connection connection;

    public void init() throws Exception {

        Properties info = new Properties();

        logger.info("Parameters:");
        for (String name : config.getParameterNames()) {
            String value = config.getParameter(name);
            logger.info("- " + name + ": " + value);
            info.put(name, value);
        }

        String url = (String) info.remove("url");
        logger.info("Connecting to " + url);
        connection = DriverManager.getConnection(url, info);

        DatabaseMetaData md = connection.getMetaData();
        ResultSet rs = null;

        try {
            logger.info("Tables:");
            rs = md.getTables(null, null, "%", new String[] { "TABLE" });

            while (rs.next()) {
                String name = rs.getString(3);
                logger.info("- " + name);
            }

        } finally {
            if (rs != null) rs.close();
        }
    }

    public void close() throws Exception {
        connection.close();
    }

    public ACMENonce getNonce(String value) throws Exception {

        logger.info("Getting nonce " + value);

        String sql = "select \"expires\" from \"nonces\" where \"value\"=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, value);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                ACMENonce nonce = new ACMENonce();
                nonce.setValue(value);

                Timestamp expires = rs.getTimestamp("expires");
                nonce.setExpirationTime(new Date(expires.getTime()));

                return nonce;
            }
        }
    }

    public void addNonce(ACMENonce nonce) throws Exception {

        String json = nonce.toJSON();
        logger.info("Adding nonce: " + json);

        String sql = "insert into \"nonces\" (\"value\", \"expires\") values (?, ?)";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, nonce.getValue());

            Date expirationTime = nonce.getExpirationTime();
            ps.setTimestamp(2, new Timestamp(expirationTime.getTime()));

            ps.executeUpdate();
        }
    }

    public ACMENonce removeNonce(String value) throws Exception {

        ACMENonce nonce = getNonce(value);

        if (nonce == null) {
            return null;
        }

        logger.info("Removing nonce: " + value);

        String sql = "delete from \"nonces\" where \"value\"=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, value);
            ps.executeUpdate();
        }

        return nonce;
    }

    public void removeExpiredNonces(Date currentTime) throws Exception {

        logger.info("Removing expired nonces: " + currentTime);

        Collection<ACMENonce> list = new ArrayList<>();

        String sql = "select \"value\", \"expires\" from \"nonces\" where \"expires\"<=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setTimestamp(1, new Timestamp(currentTime.getTime()));

            try (ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {

                    ACMENonce nonce = new ACMENonce();

                    String value = rs.getString("value");
                    nonce.setValue(value);

                    Timestamp expires = rs.getTimestamp("expires");
                    nonce.setExpirationTime(new Date(expires.getTime()));

                    list.add(nonce);
                }
            }
        }

        for (ACMENonce nonce : list) {
            removeNonce(nonce.getValue());
        }
    }

    public ACMEAccount getAccount(String accountID) throws Exception {

        logger.info("Getting account: " + accountID);

        ACMEAccount account = new ACMEAccount();

        String sql = "select \"status\", \"orders\", \"jwk\" from \"accounts\" where \"id\"=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, accountID);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                account.setID(accountID);
                account.setStatus(rs.getString("status"));
                account.setOrders(new URI(rs.getString("orders")));

                String jwk = rs.getString("jwk");
                account.setJWK(JWK.fromJSON(jwk));
            }
        }

        sql = "select \"contact\" from \"account_contacts\" where \"account_id\"=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, accountID);

            try (ResultSet rs = ps.executeQuery()) {

                List<String> contacts = new ArrayList<>();

                while (rs.next()) {
                    String contact = rs.getString("contact");
                    contacts.add(contact);
                }

                if (contacts.isEmpty()) {
                    account.setContact(contacts.toArray(new String[contacts.size()]));
                }
            }
        }

        return account;
    }

    public void addAccount(ACMEAccount account) throws Exception {

        String accountID = account.getID();

        String json = account.toJSON();
        logger.info("Adding account: " + json);

        String sql = "insert into \"accounts\" (\"id\", \"status\", \"orders\", \"jwk\") values (?, ?, ?, ?)";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, accountID);
            ps.setString(2, account.getStatus());
            ps.setString(3, account.getOrders().toString());
            ps.setString(4, account.getJWK().toJSON());

            ps.executeUpdate();
        }

        String[] contacts = account.getContact();
        if (contacts != null) {
            for (String contact : contacts) {

                sql = "insert into \"account_contacts\" (\"account_id\", \"contact\") values (?, ?)";
                logger.info("SQL: " + sql);

                try (PreparedStatement ps = connection.prepareStatement(sql)) {

                    ps.setString(1, accountID);
                    ps.setString(2, contact);

                    ps.executeUpdate();
                }
            }
        }
    }

    public ACMEOrder getOrder(String orderID) throws Exception {

        logger.info("Getting order: " + orderID);

        ACMEOrder order = new ACMEOrder();

        String sql = "select \"account_id\", \"status\", \"expires\", \"not_before\", \"not_after\", " +
                "\"finalize\", \"csr\", \"certificate\", \"resource\" from \"orders\" where \"id\"=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, orderID);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                order.setID(orderID);
                order.setAccountID(rs.getString("account_id"));
                order.setStatus(rs.getString("status"));

                Timestamp expires = rs.getTimestamp("expires");
                order.setExpirationTime(new Date(expires.getTime()));

                Timestamp notBefore = rs.getTimestamp("not_before");
                order.setNotBeforeTime(notBefore == null ? null : new Date(notBefore.getTime()));

                Timestamp notAfter = rs.getTimestamp("not_after");
                order.setNotAfterTime(notAfter == null ? null : new Date(notAfter.getTime()));

                String finalize = rs.getString("finalize");
                order.setFinalize(finalize == null ? null : new URI(finalize));

                order.setCSR(rs.getString("csr"));

                String certificate = rs.getString("certificate");
                order.setCertificate(certificate == null ? null : new URI(certificate));

                String resource = rs.getString("resource");
                order.setResource(resource == null ? null : new URI(resource));
            }
        }

        sql = "select \"type\", \"value\" from \"order_identifiers\" where \"order_id\"=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, orderID);

            try (ResultSet rs = ps.executeQuery()) {

                List<ACMEIdentifier> identifiers = new ArrayList<>();

                while (rs.next()) {
                    ACMEIdentifier identifier = new ACMEIdentifier();
                    identifier.setType(rs.getString("type"));
                    identifier.setValue(rs.getString("value"));
                    identifiers.add(identifier);
                }

                if (!identifiers.isEmpty()) {
                    order.setIdentifiers(identifiers.toArray(new ACMEIdentifier[identifiers.size()]));
                }
            }
        }

        sql = "select \"url\" from \"order_authorizations\" where \"order_id\"=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, orderID);

            try (ResultSet rs = ps.executeQuery()) {

                List<URI> authorizations = new ArrayList<>();

                while (rs.next()) {
                    URI authorization = new URI(rs.getString("url"));
                    authorizations.add(authorization);
                }

                if (!authorizations.isEmpty()) {
                    order.setAuthorizations(authorizations.toArray(new URI[authorizations.size()]));
                }
            }
        }

        return order;
    }

    public ACMEOrder getOrderByAuthorization(URI authzURI) throws Exception {

        logger.info("Getting order: " + authzURI);

        ACMEOrder order = new ACMEOrder();

        String sql = "select o.\"id\", o.\"account_id\", o.\"status\", o.\"expires\", o.\"not_before\", o.\"not_after\", " +
                "o.\"finalize\", o.\"csr\", o.\"certificate\", o.\"resource\" from \"orders\" o, \"order_authorizations\" oa " +
                "where o.\"id\"=oa.\"order_id\" and oa.\"url\"=?";
        logger.info("SQL: " + sql);

        String orderID;

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, authzURI.toString());

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                orderID = rs.getString("id");

                order.setID(orderID);
                order.setAccountID(rs.getString("account_id"));
                order.setStatus(rs.getString("status"));

                Timestamp expires = rs.getTimestamp("expires");
                order.setExpirationTime(new Date(expires.getTime()));

                Timestamp notBefore = rs.getTimestamp("not_before");
                order.setNotBeforeTime(notBefore == null ? null : new Date(notBefore.getTime()));

                Timestamp notAfter = rs.getTimestamp("not_after");
                order.setNotAfterTime(notAfter == null ? null : new Date(notAfter.getTime()));

                String finalize = rs.getString("finalize");
                order.setFinalize(finalize == null ? null : new URI(finalize));

                order.setCSR(rs.getString("csr"));

                String certificate = rs.getString("certificate");
                order.setCertificate(certificate == null ? null : new URI(certificate));

                String resource = rs.getString("resource");
                order.setResource(resource == null ? null : new URI(resource));
            }
        }

        sql = "select \"type\", \"value\" from \"order_identifiers\" where \"order_id\"=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, orderID);

            try (ResultSet rs = ps.executeQuery()) {

                List<ACMEIdentifier> identifiers = new ArrayList<>();

                while (rs.next()) {
                    ACMEIdentifier identifier = new ACMEIdentifier();
                    identifier.setType(rs.getString("type"));
                    identifier.setValue(rs.getString("value"));
                    identifiers.add(identifier);
                }

                if (!identifiers.isEmpty()) {
                    order.setIdentifiers(identifiers.toArray(new ACMEIdentifier[identifiers.size()]));
                }
            }
        }

        sql = "select \"url\" from \"order_authorizations\" where \"order_id\"=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, orderID);

            try (ResultSet rs = ps.executeQuery()) {

                List<URI> authorizations = new ArrayList<>();

                while (rs.next()) {
                    URI authorization = new URI(rs.getString("url"));
                    authorizations.add(authorization);
                }

                if (!authorizations.isEmpty()) {
                    order.setAuthorizations(authorizations.toArray(new URI[authorizations.size()]));
                }
            }
        }

        return order;
    }

    public void addOrder(ACMEOrder order) throws Exception {

        String orderID = order.getID();

        String json = order.toJSON();
        logger.info("Adding order: " + json);

        String sql = "insert into \"orders\" " +
                "(\"id\", \"account_id\", \"status\", \"expires\", \"not_before\", \"not_after\", " +
                "\"finalize\", \"csr\", \"certificate\", \"resource\") values " +
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, orderID);
            ps.setString(2, order.getAccountID());
            ps.setString(3, order.getStatus());

            Date expirationTime = order.getExpirationTime();
            ps.setTimestamp(4, new Timestamp(expirationTime.getTime()));

            Date notBefore = order.getNotBeforeTime();
            ps.setTimestamp(5, notBefore == null ? null : new Timestamp(notBefore.getTime()));

            Date notAfter = order.getNotAfterTime();
            ps.setTimestamp(6, notAfter == null ? null : new Timestamp(notAfter.getTime()));

            URI finalize = order.getFinalize();
            ps.setString(7, finalize == null ? null : finalize.toString());

            ps.setString(8, order.getCSR());

            URI certificate = order.getCertificate();
            ps.setString(9, certificate == null ? null : certificate.toString());

            URI resource = order.getResource();
            ps.setString(10, resource == null ? null : resource.toString());

            ps.executeUpdate();
        }

        ACMEIdentifier[] identifiers = order.getIdentifiers();
        if (identifiers != null) {
            for (ACMEIdentifier identifier : identifiers) {

                sql = "insert into \"order_identifiers\" (\"order_id\", \"type\", \"value\") values (?, ?, ?)";
                logger.info("SQL: " + sql);

                try (PreparedStatement ps = connection.prepareStatement(sql)) {

                    ps.setString(1, orderID);
                    ps.setString(2, identifier.getType());
                    ps.setString(3, identifier.getValue());

                    ps.executeUpdate();
                }
            }
        }

        URI[] authorizations = order.getAuthorizations();
        if (authorizations != null) {
            for (URI authorization : authorizations) {

                sql = "insert into \"order_authorizations\" (\"order_id\", \"url\") values (?, ?)";
                logger.info("SQL: " + sql);

                try (PreparedStatement ps = connection.prepareStatement(sql)) {

                    ps.setString(1, orderID);
                    ps.setString(2, authorization.toString());

                    ps.executeUpdate();
                }
            }
        }
    }

    public void updateOrder(ACMEOrder order) throws Exception {

        String orderID = order.getID();

        String json = order.toJSON();
        logger.info("Updating order: " + json);

        String sql = "update \"orders\" set \"status\"=?, \"certificate\"=? where \"id\"=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, order.getStatus());

            URI certificate = order.getCertificate();
            ps.setString(2, certificate == null ? null : certificate.toString());

            ps.setString(3, orderID);

            ps.executeUpdate();
        }
    }

    public ACMEAuthorization getAuthorization(String authzID) throws Exception {

        logger.info("Getting authorization: " + authzID);

        ACMEAuthorization authorization = new ACMEAuthorization();

        String sql = "select \"account_id\", \"status\", \"expires\", \"identifier_type\", \"identifier_value\", " +
                "\"wildcard\" from \"authorizations\" where \"id\"=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, authzID);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                authorization.setID(authzID);
                authorization.setAccountID(rs.getString("account_id"));
                authorization.setStatus(rs.getString("status"));

                Timestamp expires = rs.getTimestamp("expires");
                authorization.setExpirationTime(new Date(expires.getTime()));

                ACMEIdentifier identifier = new ACMEIdentifier();
                identifier.setType(rs.getString("identifier_type"));
                identifier.setValue(rs.getString("identifier_value"));
                authorization.setIdentifier(identifier);

                boolean wildcard = rs.getBoolean("wildcard");
                authorization.setWildcard(wildcard ? true : null);
            }
        }

        sql = "select \"id\", \"type\", \"url\", \"token\", \"status\", \"validated\" from \"authorization_challenges\" where \"authz_id\"=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, authzID);

            try (ResultSet rs = ps.executeQuery()) {

                List<ACMEChallenge> challenges = new ArrayList<>();

                while (rs.next()) {
                    ACMEChallenge challenge = new ACMEChallenge();

                    challenge.setID(rs.getString("id"));
                    challenge.setAuthzID(authzID);
                    challenge.setType(rs.getString("type"));
                    challenge.setURL(new URI(rs.getString("url")));
                    challenge.setToken(rs.getString("token"));
                    challenge.setStatus(rs.getString("status"));

                    Timestamp validated = rs.getTimestamp("validated");
                    challenge.setValidationTime(validated == null ? null : new Date(validated.getTime()));

                    challenges.add(challenge);
                }

                if (!challenges.isEmpty()) {
                    authorization.setChallenges(challenges);
                }
            }
        }

        return authorization;
    }

    public ACMEAuthorization getAuthorizationByChallenge(URI challengeURI) throws Exception {

        logger.info("Getting authorization: " + challengeURI);

        ACMEAuthorization authorization = new ACMEAuthorization();

        String sql = "select a.\"id\", a.\"account_id\", a.\"status\", a.\"expires\", a.\"identifier_type\", a.\"identifier_value\", " +
                "a.\"wildcard\" from \"authorizations\" a, \"authorization_challenges\" ac where a.\"id\"=ac.\"authz_id\" and ac.\"url\"=?";
        logger.info("SQL: " + sql);

        String authzID;

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, challengeURI.toString());

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return null;
                }

                authzID = rs.getString("id");
                authorization.setID(authzID);
                authorization.setAccountID(rs.getString("account_id"));
                authorization.setStatus(rs.getString("status"));

                Timestamp expires = rs.getTimestamp("expires");
                authorization.setExpirationTime(new Date(expires.getTime()));

                ACMEIdentifier identifier = new ACMEIdentifier();
                identifier.setType(rs.getString("identifier_type"));
                identifier.setValue(rs.getString("identifier_value"));
                authorization.setIdentifier(identifier);

                boolean wildcard = rs.getBoolean("wildcard");
                authorization.setWildcard(wildcard ? true : null);
            }
        }

        sql = "select \"id\", \"type\", \"url\", \"token\", \"status\", \"validated\" from \"authorization_challenges\" where \"authz_id\"=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, authzID);

            try (ResultSet rs = ps.executeQuery()) {

                List<ACMEChallenge> challenges = new ArrayList<>();

                while (rs.next()) {
                    ACMEChallenge challenge = new ACMEChallenge();

                    challenge.setID(rs.getString("id"));
                    challenge.setAuthzID(authzID);
                    challenge.setType(rs.getString("type"));
                    challenge.setURL(new URI(rs.getString("url")));
                    challenge.setToken(rs.getString("token"));
                    challenge.setStatus(rs.getString("status"));

                    Timestamp validated = rs.getTimestamp("validated");
                    challenge.setValidationTime(validated == null ? null : new Date(validated.getTime()));

                    challenges.add(challenge);
                }

                if (!challenges.isEmpty()) {
                    authorization.setChallenges(challenges);
                }
            }
        }

        return authorization;
    }

    public void addAuthorization(ACMEAuthorization authorization) throws Exception {

        String authzID = authorization.getID();

        String json = authorization.toJSON();
        logger.info("Adding authorization: " + json);

        String sql = "insert into \"authorizations\" " +
                "(\"id\", \"account_id\", \"status\", \"expires\", \"identifier_type\", \"identifier_value\", \"wildcard\") values " +
                "(?, ?, ?, ?, ?, ?, ?)";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, authzID);
            ps.setString(2, authorization.getAccountID());
            ps.setString(3, authorization.getStatus());

            Date expirationTime = authorization.getExpirationTime();
            ps.setTimestamp(4, new Timestamp(expirationTime.getTime()));

            ACMEIdentifier identifier = authorization.getIdentifier();
            ps.setString(5, identifier.getType());
            ps.setString(6, identifier.getValue());

            Boolean wildcard = authorization.getWildcard();
            ps.setBoolean(7, wildcard == null ? false : wildcard);

            ps.executeUpdate();
        }

        Collection<ACMEChallenge> challenges = authorization.getChallenges();
        if (challenges != null) {
            for (ACMEChallenge challenge : challenges) {

                sql = "insert into \"authorization_challenges\" (\"id\", \"authz_id\", \"type\", \"url\", " +
                        "\"token\", \"status\", \"validated\") values " +
                        "(?, ?, ?, ?, ?, ?, ?)";
                logger.info("SQL: " + sql);

                try (PreparedStatement ps = connection.prepareStatement(sql)) {

                    ps.setString(1, challenge.getID());
                    ps.setString(2, authzID);
                    ps.setString(3, challenge.getType());
                    ps.setString(4, challenge.getURL().toString());
                    ps.setString(5, challenge.getToken());
                    ps.setString(6, challenge.getStatus());

                    Date validationTime = challenge.getValidationTime();
                    ps.setTimestamp(7, validationTime == null ? null : new Timestamp(validationTime.getTime()));

                    ps.executeUpdate();
                }
            }
        }
    }

    public void updateAuthorization(ACMEAuthorization authorization) throws Exception {

        String authzID = authorization.getID();

        String json = authorization.toJSON();
        logger.info("Updating authorization: " + json);

        String sql = "update \"authorizations\" set \"status\"=? where \"id\"=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, authorization.getStatus());
            ps.setString(2, authzID);

            ps.executeUpdate();
        }

        sql = "delete from \"authorization_challenges\" where \"authz_id\"=?";
        logger.info("SQL: " + sql);

        try (PreparedStatement ps = connection.prepareStatement(sql)) {

            ps.setString(1, authzID);

            ps.executeUpdate();
        }

        Collection<ACMEChallenge> challenges = authorization.getChallenges();
        if (challenges != null) {
            for (ACMEChallenge challenge : challenges) {

                sql = "insert into \"authorization_challenges\" (\"id\", \"authz_id\", \"type\", \"url\", " +
                        "\"token\", \"status\", \"validated\") values " +
                        "(?, ?, ?, ?, ?, ?, ?)";
                logger.info("SQL: " + sql);

                try (PreparedStatement ps = connection.prepareStatement(sql)) {

                    ps.setString(1, challenge.getID());
                    ps.setString(2, authzID);
                    ps.setString(3, challenge.getType());
                    ps.setString(4, challenge.getURL().toString());
                    ps.setString(5, challenge.getToken());
                    ps.setString(6, challenge.getStatus());

                    Date validationTime = challenge.getValidationTime();
                    ps.setTimestamp(7, validationTime == null ? null : new Timestamp(validationTime.getTime()));

                    ps.executeUpdate();
                }
            }
        }
    }
}
