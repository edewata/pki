getNonce=\
SELECT \
    expires \
FROM \
    nonces \
WHERE \
    value = ?

addNonce=\
INSERT INTO \
    nonces (value, expires) \
VALUES \
    (?, ?)

removeNonce=\
DELETE FROM \
    nonces \
WHERE \
    value = ?

removeExpiredNonces=\
SELECT \
    value, expires \
FROM \
    nonces \
WHERE \
    expires <= ?

getAccount=\
SELECT \
    status, orders, jwk \
FROM \
    accounts \
WHERE \
    id = ?

getAccountContacts=\
SELECT \
    contact \
FROM \
    account_contacts \
WHERE \
    account_id = ?

addAccount=\
INSERT INTO \
    accounts (id, status, orders, jwk) \
VALUES \
    (?, ?, ?, ?)

addAccountContacts=\
INSERT INTO \
    account_contacts (account_id, contact) \
VALUES \
    (?, ?)

getOrder=\
SELECT \
    account_id, status, expires, not_before, not_after, \
    finalize, csr, certificate, resource \
FROM \
    orders \
WHERE \
    id = ?

getOrderIdentifiers=\
SELECT \
    type, value \
FROM \
    order_identifiers \
WHERE \
    order_id = ?

getOrderAuthorizations=\
SELECT \
    url \
FROM \
    order_authorizations \
WHERE \
    order_id = ?

getOrderByAuthorization=\
SELECT \
    o.id, o.account_id, o.status, o.expires, o.not_before, o.not_after, \
    o.finalize, o.csr, o.certificate, o.resource \
FROM \
    orders o, order_authorizations oa \
WHERE \
    o.id = oa.order_id AND oa.url = ?

addOrder=\
INSERT INTO \
    orders (id, account_id, status, expires, not_before, not_after, \
            finalize, csr, certificate, resource) \
VALUES \
    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

addOrderIdentifiers=\
INSERT INTO \
    order_identifiers (order_id, type, value) \
VALUES \
    (?, ?, ?)

addOrderAuthorizations=\
INSERT INTO \
    order_authorizations (order_id, url) \
VALUES \
    (?, ?)

updateOrder=\
UPDATE \
    orders \
SET \
    status=?, certificate=? \
WHERE \
    id = ?

getAuthorization=\
SELECT \
    account_id, status, expires, identifier_type, identifier_value, wildcard \
FROM \
    authorizations \
WHERE \
    id = ?

getAuthorizationByChallenge=\
SELECT \
    a.id, a.account_id, a.status, a.expires, a.identifier_type, a.identifier_value, a.wildcard \
FROM \
    authorizations a, authorization_challenges ac \
WHERE \
    a.id = ac.authz_id AND ac.url = ?

getAuthorizationChallenges=\
SELECT \
    id, type, url, token, status, validated \
FROM \
    authorization_challenges \
WHERE \
    authz_id = ?

addAuthorization=\
INSERT INTO \
    authorizations (id, account_id, status, expires, identifier_type, identifier_value, wildcard) \
VALUES \
    (?, ?, ?, ?, ?, ?, ?)

updateAuthorization=\
UPDATE \
    authorizations \
SET \
    status = ? \
WHERE \
    id = ?

deleteAuthorizationChallenges=\
DELETE FROM \
    authorization_challenges \
WHERE \
    authz_id = ?

addAuthorizationChallenges=\
INSERT INTO \
    authorization_challenges (id, authz_id, type, url, token, status, validated) \
VALUES \
    (?, ?, ?, ?, ?, ?, ?)
