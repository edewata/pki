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
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.key;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpEntity;
import org.dogtagpki.common.Info;
import org.dogtagpki.common.Version;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.base.RESTMessage;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.CryptoProvider;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Endi S. Dewata
 * @author Abhishek Koneru
 */
public class KeyClient extends Client {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KeyClient.class);

    public KeyRequestClient keyRequestClient;

    private CryptoProvider crypto;
    private X509Certificate transportCert;
    private EncryptionAlgorithm encryptAlgorithm;
    private KeyWrapAlgorithm wrapAlgorithm;
    private int wrapIVLength;
    private boolean useOAEP = false;

    public KeyClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "agent/keys");
        init();

        Version serverVersion = getServerVersion();
        if (serverVersion.isNewerThanOrEquals(new Version("10.4"))) {
            encryptAlgorithm = EncryptionAlgorithm.AES_128_CBC_PAD;
            wrapAlgorithm = KeyWrapAlgorithm.AES_KEY_WRAP_PAD;
            wrapIVLength = 0;
        } else {
            encryptAlgorithm = EncryptionAlgorithm.DES3_CBC;
            wrapAlgorithm = KeyWrapAlgorithm.DES3_CBC_PAD;
            wrapIVLength = 8;
        }
    }

    private Version getServerVersion() {
        Version ret = null;
        try {
            Info info = client.getInfo();
            String version = info.getVersion();
            ret = new Version(version);
        } catch (Exception e) {
            // TODO(alee) - narrow the exception here.  We should only
            // return Version(0.0.0) in the case where get a 404 response.

            // old server - may not have the Info service
            ret = new Version("0.0.0");
        }
        return ret;
    }

    public void init() throws Exception {
        keyRequestClient = new KeyRequestClient(client);
    }

    public CryptoProvider getCrypto() {
        return crypto;
    }

    public void setCrypto(CryptoProvider crypto) {
        this.crypto = crypto;
    }

    public void setTransportCert(X509Certificate transportCert) throws Exception {
        this.transportCert = transportCert;
    }

    public void setUseOAEP(boolean useOAEP) {
        this.useOAEP = useOAEP;
    }

    public boolean getUseOAEP() {
        return this.useOAEP;
    }

    /**
     * List/Search archived secrets in the DRM.
     *
     * @param clientKeyID -- Client Key Identifier
     * @param status -- Status of the keys to be listed
     * @param maxResults -- Maximum number of keys to be fetched
     * @param maxTime -- Maximum time for the operation to take
     * @param start -- Start index of list
     * @param size -- Size of the list to be returned.
     * @param realm - authz realm
     * @return a KeyInfoCollection object.
     */
    public KeyInfoCollection listKeys(
            String clientKeyID,
            String status,
            Integer maxResults,
            Integer maxTime,
            Integer start,
            Integer size,
            String realm,
            String ownerName) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (clientKeyID != null) params.put("clientKeyID", clientKeyID);
        if (status != null) params.put("status", status);
        if (maxResults != null) params.put("maxResults", maxResults);
        if (maxTime != null) params.put("maxTime", maxTime);
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);
        if (realm != null) params.put("realm", realm);
        if (ownerName != null) params.put("owner", ownerName);
        return get(null, params, KeyInfoCollection.class);
    }

    /* for backward compatibility */
    @Deprecated(since="11.5.0", forRemoval=true)
    public KeyInfoCollection listKeys(
            String clientKeyID,
            String status,
            Integer maxResults,
            Integer maxTime,
            Integer start,
            Integer size,
            String ownerName) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (clientKeyID != null) params.put("clientKeyID", clientKeyID);
        if (status != null) params.put("status", status);
        if (maxResults != null) params.put("maxResults", maxResults);
        if (maxTime != null) params.put("maxTime", maxTime);
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);
        // send ownerName as realm
        if (ownerName != null) params.put("realm", ownerName);
        return get(null, params, KeyInfoCollection.class);
    }

    /**
     * Search key requests in the DRM based on the state/type of the requests.
     *
     * @param requestState -- State of the requests to be queried.
     * @param requestType -- Type of the requests to be queried.
     * @param realm   -- Authz Realm
     * @return a KeyRequestCollection object.
     */
    public KeyRequestInfoCollection listRequests(String requestState, String requestType, String realm) throws Exception {
        return listRequests(
                requestState,
                requestType,
                null,
                new RequestId(0),
                100,
                100,
                10,
                realm);
    }

    /* method for backwards compatibility */
    public KeyRequestInfoCollection listRequests(String requestState, String requestType) throws Exception {
        return listRequests(
                requestState,
                requestType,
                null,
                new RequestId(0),
                100,
                100,
                10,
                null);
    }

    /**
     * List/Search key requests in the DRM
     *
     * @param requestState -- State of the requests to be queried.
     * @param requestType -- Type of the requests to be queried.
     * @param clientKeyID -- Client Key Identifier
     * @param start -- Start index of list
     * @param pageSize -- Size of the list to be returned.
     * @param maxResults -- Maximum number of requests to be fetched
     * @param maxTime -- Maximum time for the operation to take
     * @param realm -- Authz Realm
     * @return a KeyRequestInfoCollection object.
     */
    public KeyRequestInfoCollection listRequests(
            String requestState,
            String requestType,
            String clientKeyID,
            RequestId start,
            Integer pageSize,
            Integer maxResults,
            Integer maxTime,
            String realm) throws Exception {
        return keyRequestClient.listRequests(
                requestState,
                requestType,
                clientKeyID,
                start,
                pageSize,
                maxResults,
                maxTime,
                realm);
    }

    /**
     * Return a KeyRequestInfo object for a specific request.
     *
     * @param id -- A Request Id object
     * @return the KeyRequestInfo object for a specific request.
     */
    public KeyRequestInfo getRequestInfo(RequestId id) throws Exception {
        return keyRequestClient.getRequestInfo(id);
    }

    /**
     * Get the info in the KeyRecord for a specific secret in the DRM.
     *
     * @param id -- key id for secret
     * @return the KeyInfo object for a specific request.
     */
    public KeyInfo getKeyInfo(KeyId id) throws Exception {
        if (id == null) {
            throw new IllegalArgumentException("Key Id must be specified.");
        }
        return get(id.toHexString(), KeyInfo.class);
    }

    /**
     * Get the info in the KeyRecord for the active secret in the DRM.
     *
     * @param clientKeyID -- Client Key Identifier
     */
    public KeyInfo getActiveKeyInfo(String clientKeyID) throws Exception {
        if (clientKeyID == null) {
            throw new IllegalArgumentException("Client Key Id must be specified.");
        }
        return get("active/" + clientKeyID, KeyInfo.class);
    }

    /**
     * Modify the status of a key
     *
     * @param id -- key id for secret
     * @param status -- Status to be set for the key
     */
    public void modifyKeyStatus(KeyId id, String status) throws Exception {
        if (id == null || status == null) {
            throw new IllegalArgumentException("Key Id and status must be specified.");
        }
        if (!status.equalsIgnoreCase(KeyResource.KEY_STATUS_ACTIVE)
                && !status.equalsIgnoreCase(KeyResource.KEY_STATUS_INACTIVE)) {
            throw new IllegalArgumentException("Invalid status value.");
        }
        Map<String, Object> params = new HashMap<>();
        if (status != null) params.put("status", status);
        post(id.toHexString(), params, null, Void.class);
    }

    /**
     * Approve a secret recovery request
     *
     * @param id -- Id of the request
     */
    public void approveRequest(RequestId id) throws Exception {
        keyRequestClient.approveRequest(id);
    }

    /**
     * Reject a secret recovery request
     *
     * @param id -- Id of the request
     */
    public void rejectRequest(RequestId id) throws Exception {
        keyRequestClient.rejectRequest(id);
    }

    /**
     * Cancel a secret recovery request
     *
     * @param id -- Id of the request
     */
    public void cancelRequest(RequestId id) throws Exception {
        keyRequestClient.cancelRequest(id);
    }

    /**
     * Submit an archival, recovery or key generation request
     * to the DRM.
     *
     * @param data -- A KeyArchivalRequest/KeyRecoveryRequest/SymKeyGenerationRequest object
     * @return A KeyRequestResponse object
     */
    private KeyRequestResponse submitRequest(RESTMessage request) throws Exception {
        return keyRequestClient.submitRequest(request);
    }

    /**
     * Create a request to recover a secret.
     *
     * To retrieve a symmetric key or passphrase, the only parameter that is required is
     * the KeyId object. It is possible (but not required) to pass in the session keys/passphrase
     * and nonceData for the retrieval at this time.
     *
     * To retrieve an asymmetric key, the keyId and the the base-64 encoded certificate
     * is required.
     *
     * @param keyId -- key id for secret
     * @param sessionWrappedPassphrase -- A passphrase wrapped by a session key
     * @param transWrappedSessionKey -- The session key, used to wrap the passphrase, wrapped by the DRM transport cert.
     * @param nonceData -- IV parameter used while encrypting the passphrase using the session key.
     * @param b64Certificate -- A certificate in encoded using Base64
     * @return A KeyRequestResponse object containing information about the key request and the key.
     */
    public KeyRequestResponse recoverKey(KeyId keyId, byte[] sessionWrappedPassphrase, byte[] transWrappedSessionKey,
            byte[] nonceData, String b64Certificate) throws Exception {
        // create recovery request
        if (keyId == null) {
            throw new IllegalArgumentException("KeyId nust be specified.");
        }
        KeyRecoveryRequest data = new KeyRecoveryRequest();
        data.setKeyId(keyId);
        if (sessionWrappedPassphrase != null) {
            data.setSessionWrappedPassphrase(Utils.base64encode(sessionWrappedPassphrase, false));
        }
        if (transWrappedSessionKey != null) {
            data.setTransWrappedSessionKey(Utils.base64encode(transWrappedSessionKey, false));
        }

        if (nonceData != null) {
            data.setNonceData(Utils.base64encode(nonceData, false));
        }
        if (b64Certificate != null) {
            data.setCertificate(b64Certificate);
        }

        return submitRequest(data);
    }

    /**
     * Retrieve a secret from the DRM.
     *
     * @param data -- a KeyRecoveryRequest containing the keyId of the
     *            secret being retrieved, the request_id of the approved recovery
     *            request and a wrapping mechanism.
     * @return A Key object containing the wrapped secret.
     */
    public KeyData retrieveKeyData(KeyRecoveryRequest data) throws Exception {

        if (data == null) {
            throw new IllegalArgumentException("A KeyRecoveryRequest object must be specified");
        }

        logger.info("Submitting key retrieval request to KRA");

        HttpEntity entity = client.entity(data);
        return post("retrieve", null, entity, KeyData.class);
    }

    public SymmetricKey generateSessionKey() throws Exception {
        return crypto.generateSessionKey(encryptAlgorithm);
    }

    /**
     * Retrieve a secret (passphrase or symmetric key) from the DRM.
     *
     * To ensure data security in transit, the data will be returned encrypted by a session
     * key (168 bit 3DES symmetric key) - which is first wrapped (encrypted) by the public
     * key of the DRM transport certificate before being sent to the DRM.
     *
     * This method will call CryptoUtil methods to generate the session key and wrap it
     * with the DRM transport cert. The function will return the Key object, but with the secret
     * set to the variable data. (The decryption of the encryptedData is done
     * on the client side i.e. the secret is not transmitted as it is by the server.)
     *
     * @param keyId -- key id for secret
     * @return A Key object containing the unwrapped secret (set to the attribute data).
     * @throws Exception - Exceptions of type NoSuchAlgorithmException, IllegalStateException, TokenException,
     *             CertificateEncodingException, InvalidKeyException, InvalidAlgorithmParameterException,
     *             BadPaddingException, IllegalBlockSizeException
     */
    public KeyData retrieveKey(KeyId keyId, SymmetricKey sessionKey) throws Exception {

        logger.info("Retrieving key " + keyId + " with session key");

        if (keyId == null) {
            throw new IllegalArgumentException("KeyId must be specified.");
        }

        logger.info("Wrapping session key with transport certificate");

	KeyWrapAlgorithm alg = KeyWrapAlgorithm.RSA;

        if(this.useOAEP == true) {
            alg = KeyWrapAlgorithm.RSA_OAEP;
        }

        byte[] transWrappedSessionKey = crypto.wrapSymmetricKey(sessionKey, transportCert.getPublicKey(),alg);

        return retrieveKey(keyId, transWrappedSessionKey);
    }

    public void processKeyData(Key data, SymmetricKey sessionKey) throws Exception {
        if (data.getEncryptedData() == null)
            return;

        if (data.getWrapAlgorithm() == null) {
            // data was encrypted
            data.setData(crypto.unwrapWithSessionKey(data.getEncryptedData(), sessionKey,
                    encryptAlgorithm, data.getNonceData()));
            return;
        }

        // data was key-wrapped and is a private or symmetric key
        byte[] bytes = null;

        if (data.getType().equalsIgnoreCase(KeyRequestResource.SYMMETRIC_KEY_TYPE)) {
            bytes = crypto.unwrapSymmetricKeyWithSessionKey(
                    data.getEncryptedData(),
                    sessionKey,
                    KeyWrapAlgorithm.fromString(data.getWrapAlgorithm()),
                    data.getNonceData(),
                    data.getAlgorithm(),
                    data.getSize());
        } else {
            // private key in asymmetric key pair

            // get public key from key_info
            // TODO(alee) This assumes RSA for now

            byte[] pubKeyBytes = Utils.base64decode(data.getPublicKey());
            PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(
                    new X509EncodedKeySpec(pubKeyBytes));

            bytes = crypto.unwrapAsymmetricKeyWithSessionKey(
                    data.getEncryptedData(),
                    sessionKey,
                    KeyWrapAlgorithm.fromString(data.getWrapAlgorithm()),
                    data.getNonceData(),
                    pubKey);
        }

        data.setData(bytes);
    }

    public KeyData retrieveKeyByRequest(RequestId requestId, SymmetricKey sessionKey) throws Exception {

        if (requestId == null) {
            throw new IllegalArgumentException("RequestId must be specified.");
        }

        KeyWrapAlgorithm alg = KeyWrapAlgorithm.RSA;

        if(this.useOAEP == true) {
            alg = KeyWrapAlgorithm.RSA_OAEP;
        }

        byte[] transWrappedSessionKey = crypto.wrapSymmetricKey(sessionKey, transportCert.getPublicKey(),alg);

        KeyRecoveryRequest recoveryRequest = new KeyRecoveryRequest();
        recoveryRequest.setRequestId(requestId);
        recoveryRequest.setTransWrappedSessionKey(Utils.base64encode(transWrappedSessionKey, false));
        recoveryRequest.setPayloadEncryptionOID(getEncryptAlgorithmOID());
        recoveryRequest.setPayloadWrappingName(wrapAlgorithm.toString());

        return retrieveKeyData(recoveryRequest);
    }

    /**
     * Retrieve a secret (passphrase or symmetric key) from the DRM.
     *
     * This function generates a key recovery request, approves it, and retrieves
     * the secret referred to by keyId.
     * This assumes that only one approval is required to authorize the recovery.
     *
     * The parameter transWrappedSessionKey refers to the session key wrapped with the transport cert.
     *
     * The method will simply pass the data to the DRM, and will return the secret
     * wrapped in the session key. The secret will still need to be unwrapped by the caller.
     *
     * @param keyId -- key id for secret
     * @param transWrappedSessionKey -- session key wrapped by the transport cert.
     * @return A Key object containing the wrapped secret.
     * @throws Exception - Exceptions of type NoSuchAlgorithmException, IllegalStateException, TokenException,
     *             CertificateEncodingException, InvalidKeyException, InvalidAlgorithmParameterException,
     *             BadPaddingException, IllegalBlockSizeException
     */
    public KeyData retrieveKey(KeyId keyId, byte[] transWrappedSessionKey) throws Exception {

        logger.info("Retrieving key " + keyId + " with session key wrapped by transport certificate");

        if (keyId == null) {
            throw new IllegalArgumentException("KeyId must be specified.");
        }

        if (transWrappedSessionKey == null) {
            throw new IllegalArgumentException("A transport cert wrapped session key cannot be null.");
        }

        KeyRecoveryRequest recoveryRequest = new KeyRecoveryRequest();
        recoveryRequest.setKeyId(keyId);
        recoveryRequest.setTransWrappedSessionKey(Utils.base64encode(transWrappedSessionKey, false));
        recoveryRequest.setPayloadEncryptionOID(getEncryptAlgorithmOID());
        recoveryRequest.setPayloadWrappingName(getWrapAlgorithmName());

        return retrieveKeyData(recoveryRequest);
    }

    /**
     *
     * The secret is secured in transit by wrapping the secret with the passphrase using
     * PBE encryption.
     *
     * CryptoUtil methods will be called to create the data to securely send the
     * passphrase to the DRM. Basically, three pieces of data will be sent:
     *
     * - the passphrase wrapped by a 168 bit 3DES symmetric key (the session key).
     * - the session key wrapped with the public key in the DRM transport certificate.
     * - an ivps vector to be used as nonceData.
     *
     * @param keyId -- key id of secret.
     * @param passphrase -- passphrase used to wrap the secret in the response.
     * @return A Key object with the secret wrapped with the passphrase.
     * @throws Exception - Exceptions of type NoSuchAlgorithmException, IllegalStateException, TokenException,
     *             CertificateEncodingException, InvalidKeyException, InvalidAlgorithmParameterException,
     *             BadPaddingException, IllegalBlockSizeException
     */
    public KeyData retrieveKeyByPassphrase(KeyId keyId, String passphrase) throws Exception {
        if (keyId == null) {
            throw new IllegalArgumentException("KeyId must be specified.");
        }
        if (passphrase == null) {
            throw new IllegalArgumentException("Passphrase must be specified.");
        }
        KeyWrapAlgorithm alg = KeyWrapAlgorithm.RSA;

        if(this.useOAEP == true) {
            alg = KeyWrapAlgorithm.RSA_OAEP;
        }

        SymmetricKey sessionKey = generateSessionKey();
        byte[] transWrappedSessionKey = crypto.wrapSymmetricKey(sessionKey, transportCert.getPublicKey(),alg);
        byte[] nonceData = CryptoUtil.getNonceData(encryptAlgorithm.getIVLength());

        byte[] secret = passphrase.getBytes("UTF-8");
        byte[] sessionWrappedPassphrase = crypto.encryptSecret(secret, nonceData, sessionKey,
                encryptAlgorithm);

        return retrieveKeyUsingWrappedPassphrase(keyId, transWrappedSessionKey, sessionWrappedPassphrase, nonceData);
    }

    public Key retrieveKeyByRequestWithPassphrase(RequestId requestId, String passphrase) throws Exception {
        if (requestId == null) {
            throw new IllegalArgumentException("RequestId must be specified.");
        }
        if (passphrase == null) {
            throw new IllegalArgumentException("Passphrase must be specified.");
        }
        KeyWrapAlgorithm alg = KeyWrapAlgorithm.RSA;

        if(this.useOAEP == true) {
            alg = KeyWrapAlgorithm.RSA_OAEP;
        }

        SymmetricKey sessionKey = generateSessionKey();
        byte[] transWrappedSessionKey = crypto.wrapSymmetricKey(sessionKey, transportCert.getPublicKey(),alg);
        byte[] nonceData = CryptoUtil.getNonceData(encryptAlgorithm.getIVLength());

        byte[] secret = passphrase.getBytes("UTF-8");
        byte[] sessionWrappedPassphrase = crypto.encryptSecret(secret, nonceData, sessionKey,
                encryptAlgorithm);

        KeyRecoveryRequest data = new KeyRecoveryRequest();
        data.setRequestId(requestId);
        data.setTransWrappedSessionKey(Utils.base64encode(transWrappedSessionKey, false));
        data.setSessionWrappedPassphrase(Utils.base64encode(sessionWrappedPassphrase, false));
        data.setNonceData(Utils.base64encode(nonceData, false));
        data.setPayloadEncryptionOID(getEncryptAlgorithmOID());
        data.setPayloadWrappingName(wrapAlgorithm.toString());

        return new Key(retrieveKeyData(data));
    }

    /**
     *
     * This method generates a key recovery request, approves it, and retrieves
     * the secret referred to by keyId. This assumes that only one approval is required
     * to authorize the recovery.
     *
     * The method will return the secret encrypted by the passphrase using
     * PBE Encryption. The secret will still need to be decrypted by the caller.
     *
     * @param keyId -- key id for secret
     * @param transWrappedSessionKey -- Session key wrapped with the transport cert
     * @param sessionWrappedPassphrase -- Passphrase wrapped with the session key
     * @param nonceData -- nonce data used for encryption.
     * @return A Key object with the secret wrapped by the passphrase provided.
     * @throws Exception - Exceptions of type NoSuchAlgorithmException, IllegalStateException, TokenException,
     *             CertificateEncodingException, InvalidKeyException, InvalidAlgorithmParameterException,
     *             BadPaddingException, IllegalBlockSizeException
     */
    public KeyData retrieveKeyUsingWrappedPassphrase(KeyId keyId, byte[] transWrappedSessionKey,
            byte[] sessionWrappedPassphrase, byte[] nonceData) throws Exception {

        if (keyId == null) {
            throw new IllegalArgumentException("KeyId has to be specified.");
        }

        if (sessionWrappedPassphrase == null) {
            throw new IllegalArgumentException("Session key wrapped passphrase must be specified.");

        }
        if (transWrappedSessionKey == null || nonceData == null) {
            throw new IllegalArgumentException(
                    "No way to extract passphrase. Both transWrappedSessionKey and nonceData must be specified.");
        }

        // Need to pass the sessionWrappedPassphrase and transWrappedSessionKey when the
        // both request and recovery are done at the same time. So the KeyRequestResounse itself
        // contains the KeyData
        RequestId requestId = recoverKey(keyId, null, null, null, null).getRequestId();
        approveRequest(requestId);

        KeyRecoveryRequest data = new KeyRecoveryRequest();
        data.setKeyId(keyId);
        data.setRequestId(requestId);
        data.setPayloadEncryptionOID(getEncryptAlgorithmOID());
        data.setPayloadWrappingName(wrapAlgorithm.toString());

        if (transWrappedSessionKey != null) {
            data.setTransWrappedSessionKey(Utils.base64encode(transWrappedSessionKey, false));
        }
        if (sessionWrappedPassphrase != null) {
            data.setSessionWrappedPassphrase(Utils.base64encode(sessionWrappedPassphrase, false));
        }
        if (nonceData != null) {
            data.setNonceData(Utils.base64encode(nonceData, false));
        }

        // Just return the KeyData as the wrappedPrivateData contains the key wrapped by the passphrase
        // and the the nonceData, to recover extract the key.
        return retrieveKeyData(data);
    }

    /**
     * Retrieve an asymmetric private key and return it as PKCS12 data.
     *
     * This function generates a key recovery request, approves it, and retrieves
     * the secret referred to by key_id in a PKCS12 file. This assumes that only
     * one approval is required to authorize the recovery.
     *
     * @param keyId -- key id for secret
     * @param certificate -- the certificate associated with the private key
     * @param passphrase -- A passphrase for the pkcs12 file.
     * @return A Key object with the wrapped secret
     */
    public KeyData retrieveKeyByPKCS12(KeyId keyId, String certificate, String passphrase) throws Exception {
        if (keyId == null || certificate == null || passphrase == null) {
            throw new IllegalArgumentException("KeyId, certificate and passphrase must be specified.");
        }
        KeyRequestResponse keyData = recoverKey(keyId, null, null, null, certificate);
        approveRequest(keyData.getRequestId());

        KeyRecoveryRequest recoveryRequest = new KeyRecoveryRequest();
        recoveryRequest.setKeyId(keyId);
        recoveryRequest.setRequestId(keyData.getRequestId());
        recoveryRequest.setPassphrase(passphrase);

        return retrieveKeyData(recoveryRequest);
    }

    /**
     * Archive a secret on the KRA.
     *
     * Requires a user-supplied client ID. There can be only one active
     * key with a specified client ID. If a record for a duplicate active
     * key exists, a BadRequestException is thrown.
     *
     *
     * @param clientKeyId -- Client Key Identfier
     * @param secret -- Secret to be archived
     * @param realm -- authorization realm
     * @return A KeyRequestResponse object with information about the request.
     * @throws Exception - Exceptions of type NoSuchAlgorithmException, IllegalStateException, TokenException,
     *             IOException, CertificateEncodingException, InvalidKeyException, InvalidAlgorithmParameterException,
     *             BadPaddingException, IllegalBlockSizeException
     */
    public KeyRequestResponse archiveSecret(String clientKeyId, byte[] secret, String realm)
            throws Exception {
        String algorithmOID = getEncryptAlgorithmOID();

        byte[] nonceData = CryptoUtil.getNonceData(encryptAlgorithm.getIVLength());
        SymmetricKey sessionKey = generateSessionKey();
	KeyWrapAlgorithm alg = KeyWrapAlgorithm.RSA;

	if(this.useOAEP == true) {
            alg = KeyWrapAlgorithm.RSA_OAEP;
        }
        byte[] transWrappedSessionKey = crypto.wrapSymmetricKey(sessionKey, transportCert.getPublicKey(),alg);

        byte[] encryptedData = crypto.encryptSecret(
                secret,
                nonceData,
                sessionKey,
                encryptAlgorithm);

        return archiveEncryptedData(clientKeyId, KeyRequestResource.PASS_PHRASE_TYPE, null, null, algorithmOID,
                nonceData, encryptedData, transWrappedSessionKey, realm);
    }

    public KeyRequestResponse archiveSecret(String clientKeyId, byte[] secret) throws Exception {
        return archiveSecret(clientKeyId, secret, null);
    }

    private String getEncryptAlgorithmOID() throws NoSuchAlgorithmException {
        String algorithmOID;
        if (encryptAlgorithm.getAlg().toString().equalsIgnoreCase("AES")) {
            // TODO(alee) - horrible hack until we figure out how to do GCM right
            // We assume the client will have AES 128 CBC with padding
            algorithmOID = EncryptionAlgorithm.AES_128_CBC.toOID().toString();
        } else {
            algorithmOID = encryptAlgorithm.toOID().toString();
        }
        return algorithmOID;
    }

    public String getWrapAlgorithmName() {
        return wrapAlgorithm.toString();
    }

    /**
     * Archive a symmetric key on the DRM.
     *
     * Requires a user-supplied client ID. There can be only one active
     * key with a specified client ID. If a record for a duplicate active
     * key exists, a BadRequestException is thrown.
     *
     * @param clientKeyId -- Client Key Identifier
     * @param keyAlgorithm -- Algorithm used by the symmetric key
     * @param keySize -- Strength of the symmetric key (secret)
     * @param realm -- authorization realm
     * @return A KeyRequestResponse object with information about the request.
     * @throws Exception - Exceptions of type NoSuchAlgorithmException, IllegalStateException, TokenException,
     *             IOException, CertificateEncodingException, InvalidKeyException, InvalidAlgorithmParameterException,
     *             BadPaddingException, IllegalBlockSizeException
     */
    public KeyRequestResponse archiveSymmetricKey(String clientKeyId, SymmetricKey secret, String keyAlgorithm,
            Integer keySize, String realm) throws Exception {

        String algorithmOID = getEncryptAlgorithmOID();

        byte[] nonceData = null;
        if (wrapIVLength > 0) {
            nonceData = CryptoUtil.getNonceData(wrapIVLength);
        }

        KeyWrapAlgorithm alg = KeyWrapAlgorithm.RSA;

        if(this.useOAEP == true) {
            alg = KeyWrapAlgorithm.RSA_OAEP;
        }

        SymmetricKey sessionKey = generateSessionKey();
        byte[] encryptedData = crypto.wrapWithSessionKey(secret, sessionKey, nonceData, wrapAlgorithm);
        byte[] transWrappedSessionKey = crypto.wrapSymmetricKey(sessionKey, transportCert.getPublicKey(),alg);

        return archiveEncryptedData(clientKeyId, KeyRequestResource.SYMMETRIC_KEY_TYPE, keyAlgorithm, keySize,
                algorithmOID, nonceData, encryptedData, transWrappedSessionKey, realm);
    }

    /* old method signature for backwards compatibility */
    @Deprecated
    public KeyRequestResponse archiveSymmetricKey(String clientKeyId, SymmetricKey secret, String keyAlgorithm,
            Integer keySize) throws Exception {
        return archiveSymmetricKey(clientKeyId, secret, keyAlgorithm,keySize, null);
    }

    /**
     * Archive a secret (symmetric key or passphrase) on the DRM.
     *
     * This method is useful if the caller wants to do their own wrapping
     * of the secret, or if the secret was generated on a separate client
     * machine and the wrapping was done there.
     *
     * @param clientKeyId -- Client Key Identifier
     * @param dataType -- Type of secret being archived
     * @param keyAlgorithm -- Algorithm used - if the secret is a symmetric key
     * @param keySize -- Strength of the symmetric key (secret)
     * @param algorithmOID -- OID of the algorithm used for the symmetric key wrap
     * @param nonceData -- nonce data
     * @param encryptedData -- which is the secret wrapped by a session
     *            key (168 bit 3DES symmetric key)
     * @param transWrappedSessionKey -- session key wrapped by the transport cert.
     * @param realm -- authorization realm
     * @return A KeyRequestResponse object with information about the request.
     */
    public KeyRequestResponse archiveEncryptedData(
            String clientKeyId,
            String dataType,
            String keyAlgorithm,
            Integer keySize,
            String algorithmOID,
            byte[] nonceData,
            byte[] encryptedData,
            byte[] transWrappedSessionKey,
            String realm) throws Exception {

        logger.info("Archiving encrypted data");

        if (clientKeyId == null || dataType == null) {
            throw new IllegalArgumentException("Client key id and data type must be specified.");
        }

        if (dataType == KeyRequestResource.SYMMETRIC_KEY_TYPE) {
            if (keyAlgorithm == null || keySize < 0) {
                throw new IllegalArgumentException(
                        "Key algorithm and key size must be specified for a symmetric key type request.");
            }
        }

        if (encryptedData == null || transWrappedSessionKey == null || algorithmOID == null
                || nonceData == null) {
            throw new IllegalArgumentException("All data and wrapping parameters must be specified.");
        }

        KeyArchivalRequest data = new KeyArchivalRequest();
        data.setDataType(dataType);
        data.setKeyAlgorithm(keyAlgorithm);
        data.setKeySize(keySize);
        data.setClientKeyId(clientKeyId);
        data.setAlgorithmOID(algorithmOID);
        data.setSymmetricAlgorithmParams(Utils.base64encode(nonceData, false));
        data.setWrappedPrivateData(Utils.base64encode(encryptedData, false));
        data.setTransWrappedSessionKey(Utils.base64encode(transWrappedSessionKey, false));
        data.setRealm(realm);

        return submitRequest(data);
    }

    /* old signature for backwards compatibility */
    @Deprecated
    public KeyRequestResponse archiveEncryptedData(String clientKeyId, String dataType, String keyAlgorithm,
            Integer keySize, String algorithmOID, byte[] nonceData, byte[] encryptedData,
            byte[] transWrappedSessionKey) throws Exception {
        return archiveEncryptedData(clientKeyId, dataType, keyAlgorithm, keySize, algorithmOID, nonceData,
                encryptedData, transWrappedSessionKey, null);
    }

    /**
     * Archive a secret (symmetric key or passphrase) on the DRM using a PKIArchiveOptions data format.
     *
     * @param clientKeyId -- Client Key Identifier
     * @param dataType -- Type of secret bring archived
     * @param keyAlgorithm -- Algorithm used if the secret is a symmetric key
     * @param keySize -- Strength of the symmetric key
     * @param pkiArchiveOptions -- is the data to be archived wrapped in a
     *            PKIArchiveOptions structure
     * @param realm -- authorization realm
     * @return A KeyRequestResponse object with information about the request.
     * @throws Exception
     */
    public KeyRequestResponse archivePKIOptions(String clientKeyId, String dataType, String keyAlgorithm, int keySize,
            byte[] pkiArchiveOptions, String realm) throws Exception {

        if (clientKeyId == null || dataType == null) {
            throw new IllegalArgumentException("Client key id and data type must be specified.");
        }
        if (dataType == KeyRequestResource.SYMMETRIC_KEY_TYPE) {
            if (keyAlgorithm == null || keySize < 0) {
                throw new IllegalArgumentException(
                        "Key algorithm and key size must be specified for a symmetric key type request.");
            }
        }
        if (pkiArchiveOptions == null) {
            throw new IllegalArgumentException(
                    "No data provided to be archived. PKIArchiveOptions data must be specified.");
        }
        KeyArchivalRequest data = new KeyArchivalRequest();

        data.setClientKeyId(clientKeyId);
        data.setDataType(dataType);
        data.setKeyAlgorithm(keyAlgorithm);
        data.setKeySize(keySize);

        String options = Utils.base64encode(pkiArchiveOptions, false);
        data.setPKIArchiveOptions(options);
        data.setRealm(realm);

        return submitRequest(data);
    }

    /* old method signature for backwards compatibility */
    @Deprecated
    public KeyRequestResponse archivePKIOptions(String clientKeyId, String dataType, String keyAlgorithm, int keySize,
            byte[] pkiArchiveOptions) throws Exception {
        return archivePKIOptions(clientKeyId, dataType, keyAlgorithm, keySize, pkiArchiveOptions, null);
    }

    /**
     * Generate and archive a symmetric key in the DRM.
     *
     * @param clientKeyId -- Client Key Identifier
     * @param keyAlgorithm -- Algorithm to be used to generate the key
     * @param keySize -- Strength of the keys
     * @param usages -- Usages of the generated key.
     * @param transWrappedSessionKey - client generated session key wrapped by
     *         KRA transport key
     * @param realm -- authorization realm
     * @return a KeyRequestResponse which contains a KeyRequestInfo
     *         object that describes the URL for the request and generated key.
     */
    public KeyRequestResponse generateSymmetricKey(String clientKeyId, String keyAlgorithm, int keySize,
            List<String> usages, String transWrappedSessionKey, String realm) throws Exception {
        if (clientKeyId == null) {
            throw new IllegalArgumentException("Client Key Identifier must be specified.");
        }
        //Validate the usages list
        List<String> validUsages = SymKeyGenerationRequest.getValidUsagesList();
        if (usages != null) {
            for (String usage : usages) {
                if (!validUsages.contains(usage)) {
                    throw new IllegalArgumentException("Invalid usage \"" + usage + "\" specified.");
                }
            }
        }
        SymKeyGenerationRequest data = new SymKeyGenerationRequest();
        data.setClientKeyId(clientKeyId);
        data.setKeyAlgorithm(keyAlgorithm);
        data.setKeySize(Integer.valueOf(keySize));
        data.setUsages(usages);
        data.setTransWrappedSessionKey(transWrappedSessionKey);

        data.setRealm(realm);

        return submitRequest(data);
    }

    /* old method signature for backwards compatibility */
    @Deprecated
    public KeyRequestResponse generateSymmetricKey(String clientKeyId, String keyAlgorithm, int keySize,
            List<String> usages, String transWrappedSessionKey) throws Exception {
        return generateSymmetricKey(clientKeyId, keyAlgorithm, keySize, usages, transWrappedSessionKey, null);
    }

    /**
     * Generate and archive an asymmetric keys in the DRM
     *
     * @param clientKeyId -- Client Key Identifier
     * @param keyAlgorithm -- Algorithm to be used to generate the asymmetric keys
     * @param keySize -- Strength of the keys
     * @param usages  -- key usages
     * @param transWrappedSessionKey  -- client generated session key wrapped by the
     *        KRA transport key
     * @param realm  -- authorization realm
     */
    public KeyRequestResponse generateAsymmetricKey(String clientKeyId, String keyAlgorithm, int keySize,
            List<String> usages, byte[] transWrappedSessionKey, String realm) throws Exception {

        if (clientKeyId == null) {
            throw new IllegalArgumentException("Client Key Identifier must be specified.");
        }

        //Validate the usages list
        List<String> validUsages = AsymKeyGenerationRequest.getValidUsagesList();
        if (usages != null) {
            for (String usage : usages) {
                if (!validUsages.contains(usage)) {
                    throw new IllegalArgumentException("Invalid usage \"" + usage + "\" specified.");
                }
            }
        }
        if (!(keyAlgorithm.equals(KeyRequestResource.RSA_ALGORITHM) || keyAlgorithm
                .equals(KeyRequestResource.DSA_ALGORITHM))) {
            throw new IllegalArgumentException("Unsupported algorithm specified.");
        }

        /*
         * For RSA, JSS accepts key sizes that fall in this set of values:
         * {256 + (16 * n), where 0 <= n <= 1008
         *
         * For DSA, JSS accepts key sizes 512, 768, 1024 only, when there are no p,q,g params specified.
         */
        if (keyAlgorithm.equals(KeyRequestResource.RSA_ALGORITHM)) {
            if (keySize >= 256) {
                if ((keySize - 256) % 16 != 0) {
                    throw new IllegalArgumentException("Invalid key size specified.");
                }
            } else {
                throw new IllegalArgumentException("Invalid key size specified.");
            }
        } else if (keyAlgorithm.equals(KeyRequestResource.DSA_ALGORITHM)) {
            if (keySize != 512 && keySize != 768 && keySize != 1024) {
                throw new IllegalArgumentException("Invalid key size specified.");
            }
        }
        AsymKeyGenerationRequest data = new AsymKeyGenerationRequest();
        data.setClientKeyId(clientKeyId);
        data.setKeyAlgorithm(keyAlgorithm);
        data.setKeySize(keySize);
        data.setUsages(usages);
        if (transWrappedSessionKey !=null) {
            // Caller by default calls in with transWrappedSessionKey null;
            // And the underlying Java code does not like null;
            data.setTransWrappedSessionKey(Utils.base64encode(transWrappedSessionKey, false));
        }
        data.setRealm(realm);

        return submitRequest(data);
    }

    /* old method signature for backwards compatibility */
    @Deprecated
    public KeyRequestResponse generateAsymmetricKey(String clientKeyId, String keyAlgorithm, int keySize,
            List<String> usages, byte[] transWrappedSessionKey) throws Exception {
        return generateAsymmetricKey(clientKeyId, keyAlgorithm, keySize, usages, transWrappedSessionKey, null);
    }
}
