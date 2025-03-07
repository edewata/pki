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
// (C) 2020 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.def;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.util.Locale;
import java.util.Vector;

import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.netscape.security.provider.DSAPublicKey;
import org.mozilla.jss.netscape.security.provider.RSAPublicKey;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cms.profile.common.PolicyDefaultConfig;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * This class implements an enrollment default policy
 * for Server-Side keygen enrollment.
 * It accepts usre-supplied key type and size to be passed onto KRA
 *
 * @author Christina Fu
 */
public class ServerKeygenUserKeyDefault extends EnrollDefault {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ServerKeygenUserKeyDefault.class);

    public static final String CONFIG_ENABLE_ARCHIVAL = "enableArchival";
    public static final String CONFIG_LEN = "keySize";
    public static final String CONFIG_TYPE = "keyType";
    public static final String VAL_LEN = "LEN";
    public static final String VAL_TYPE = "TYPE";

    //  DO NOT REMOVE
    private static final String TEMP_PUBKEY_RSA_1024 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBz6H2rT2r1RpHdr3JyYr7thSjfwWPbIJ6U09NziHSekLsNZQKsjdLS/LPCfe/aXkhpzPztlx++tkPucpt/xT0exp08feAPIE+Y6gVoyXzEw+Ztz+Zez9Y1cQWxAyp7z11flytjL+4zBGDXmEoe3ZlQvij9DGypPjBC9PhWm0lBwIDAQAB";
    private static final String TEMP_PUBKEY_RSA_2048 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4Ha+CxWDPAHEl9+u57U3UCw8bfG/ZN3cVTrQgj/p8ak12NYUWt0ZI/xCcLj7gKwFPbNMTDwzizRPZuxKJT7fHgW8a1BQDUL2VGfx7O0A7KlLqcpVc6VKsQx5caP3hrB38Q5xnTKeVee9cBrd8An+veZ2QV6mHLEU8iMCN2No/t1oO+aYje42XloNRblXVQAOYW+3aMCam2kIKWUqLvA3Sbf2BPR2x5SSZRPHJt3hQCheara5j+nHLQ8paRvVlT+ghgyX5N3BwiPmvC+e9iUaaofj+DxrGX3cTo5hehG2b71sY3xdC5OIhEGRfkAqIAEw6eaU6a/ymNsByRgVByfQaQIDAQAB";
    private static final String TEMP_PUBKEY_RSA_3072 = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAm0yQ0y+8YOTWkye5qFuqNI/qC4wtjEjNnoZaqSZUOJLg6ZRDlsZoOiblJpw65rPjaPcSp/inqYfCCA5mISYaqfcoB80LCnw1+DAv8tcvwUtytQYXHVj2gbyuVHaBgD4n4j/wFV80sF3OTQcPKYmeTfWRtv2xZQMK9rYfa8Le+DAZyOWPk4+RtTIRPa5R9arLqE+ONgUcrD3NvewOdsCrT7flJnFdx8TGl5ftxVWYlHRSg+wEB8pQZlw0BSDlQGHXIRjBKT2+iCkYzuKPWpMbu42PnBaQTcvjD3cl8MjLQcZp6v39bU1Du0C0LYunhvIWidwKnCOGOYu+a0VKuHxH8odjFdPoWGmP+orllkwSZzhWayYJxGpJJQlWcM05uD6qDF67WQnuYsliVH4LNiSjf/iPSpr0tzDXOtdeVsiQgO9wYYlnooBtd1xfTmkILwt3j9ZXeBtmt4lLYxbLo2ZCzkFqCCdu5FfcFgxjPaRaW0bQHKuP1woGk0rDUUbuqr+PAgMBAAE=";
    private static final String TEMP_PUBKEY_RSA_4096 = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAs3xoddtoCQrDpPK/45DpN/wPHO/6qrsbEDnwEnSkcLz51WHb7+CEUP9oxuE8vPn9JXcLdZkgPcmfMVibSUEJVUCXPibGTqAJ/7RAAm+/FhdL02N57hpgLzbIPbIaTP00z/jbTqR4a0uV49fnEPqrhA/KoUmOn3eoiAPAB5xNSauFOmMZXv2gr4akNxvSiZ/59ddYF+DBEFSs4ufCqIqBWYAMMo78eskgm/ZUyv7OZzG+8c1nncdnrNk/JtXauANu8NUQXX2qllmEOioY6gnalpR26fwOscjkvHDTvRQmSIqceWdd5P6OMHJwzTVG8d4b0f150o1RTzU3gvg9/qXvbOGcnH2TXZjYi02mhyXgPrimZepKyDr2LjeAEZbfAAXecaMhjrDZEkDZNFWe4eoG2JuE34TODeiCLMBql6VTgOvCFW3to32aBwNLpCV4hi5rKLnPMlf8Tz0zYvGqDeCp4zzy6C9tosiYfHIkVU/AVqK9PoY0RsLnBzHOV7Jl2VgHr8Ro+C66+leajssAemK8swcj2AZEOuVLlsdCvguUn6XUyDqI3tIfnoLK690hG1znuIWzFZzzivZ5ZwgfxguCly9zDArc7i6YHxOR2lcUrM0VfHmyHpE9JNfarEgAPS59ASG7y14LOvp4yYKNz10TtetwkSfpcjqiuWHtIDi9sjMCAwEAAQ==";
    private static final String TEMP_PUBKEY_EC_NISTP256 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw67JdXDj1J3wwvLTYtzpyUArev/Ra2QEsHo+q5P3VcDrr0HqJGXsj5/vH7bPe4WG5OkgxmL5BiBpKpTmJMxNLg==";
    private static final String TEMP_PUBKEY_EC_NISTP384 = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEdjuCVoP3qykxs97Wjk2k/cEE6fza0N0Y8JRzLYNrFtOti4zKNpvYcteaYTWLKYGOUEgGuOBV9lWjEbZSH5n+AqKf+JLaTu+Qytsr9OnBu3L4r18yNdWQQo/LlaLkr5on";
    private static final String TEMP_PUBKEY_EC_NISTP521 = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAnGS6GRhXMwgKu+0G7BHWbu99h4KoZi4vzKvJ+QmoApZbaU0A83ayHhKp6c5mubgZY7Vq1/msGxju89QqOf25nNwBOl9Y0IYG+/LMSjtSR1rU+MI00iyrjx3GgnC0lbxZD6KiPqMNlx5h4oyiy6d+xYfIweSF+QYVm53s4Q4OWVEhz54=";

    public ServerKeygenUserKeyDefault() {
        super();
        addConfigName(CONFIG_ENABLE_ARCHIVAL);
        addConfigName(CONFIG_TYPE);
        addConfigName(CONFIG_LEN);
        addValueName(VAL_TYPE);
        addValueName(VAL_LEN);
    }

    @Override
    public void init(CAEngineConfig engineConfig, PolicyDefaultConfig config) throws EProfileException {
        super.init(engineConfig, config);
    }

/*
    public void setConfig(String name, String value)
            throws EPropertyException {
        super.setConfig(name, value);
    }
*/

    @Override
    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_ENABLE_ARCHIVAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale,
                    "CMS_PROFILE_SERVER_SIDE_KEYGEN_ENABLE_ARCHIVAL"));
        } else if (name.equals(CONFIG_TYPE)) {
            return new Descriptor(IDescriptor.STRING,
                    null,
                    "RSA",
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_SERVER_SIDE_KEYGEN_KEYTYPE"));
        } else if (name.equals(CONFIG_LEN)) {
            return new Descriptor(IDescriptor.STRING,
                    null,
                    "2048",
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_SERVER_SIDE_KEYGEN_KEYSIZE"));
        } else  {
            return null;
        }
    }

    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_LEN)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_LEN"));
        } else if (name.equals(VAL_TYPE)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_TYPE"));
        } else {
            return null;
        }
    }

    @Override
    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        // this default rule is readonly
    }

    @Override
    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        logger.debug("ServerKeygenUserKeyDefault: getValue name=" + name);
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }

        if (name.equals(VAL_LEN)) {
            CertificateX509Key ck = null;

            try {
                ck = (CertificateX509Key)
                        info.get(X509CertInfo.KEY);
            } catch (Exception e) {
                // nothing
            }
            X509Key k = null;

            try {
                k = (X509Key)
                        ck.get(CertificateX509Key.KEY);
            } catch (Exception e) {
                // nothing
            }
            if (k == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_PROFILE_KEY_NOT_FOUND"));
            }
            try {
                if (k.getAlgorithm().equals("RSA")) {
                    return Integer.toString(getRSAKeyLen(k));
                } else if (k.getAlgorithm().equals("EC")) {
                    Vector<String> vect = CryptoUtil.getECKeyCurve(k);
                    if (vect == null) {
                        return null;
                    }
                    return vect.toString();
                } else {
                    return Integer.toString(getDSAKeyLen(k));
                }
            } catch (Exception e) {
                logger.debug("ServerKeygenUserKeyDefault: getValue " + e.toString());
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
        } else if (name.equals(VAL_TYPE)) {
            CertificateX509Key ck = null;

            try {
                ck = (CertificateX509Key)
                        info.get(X509CertInfo.KEY);
            } catch (Exception e) {
                // nothing
            }
            X509Key k = null;

            try {
                k = (X509Key)
                        ck.get(CertificateX509Key.KEY);
            } catch (Exception e) {
                // nothing
            }
            if (k == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_PROFILE_KEY_NOT_FOUND"));
            }
            return k.getAlgorithm() + " - " +
                    k.getAlgorithmId().getOID().toString();
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    @Override
    public String getText(Locale locale) {
        String[] params = {
                getConfig(CONFIG_TYPE),
                getConfig(CONFIG_LEN)
            };
        logger.debug("ServerKeygenUserKeyDefault: getText ");
        if (locale == null)
            logger.debug("ServerKeygenUserKeyDefault: getText: locale null ");

        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_SERVER_KEYGEN_USER_KEY_INFO", params);
    }

    public int getRSAKeyLen(X509Key key) throws Exception {
        X509Key newkey = null;

        try {
            newkey = new X509Key(AlgorithmId.get("RSA"),
                        key.getKey());
        } catch (Exception e) {
            logger.debug("ServerKeygenUserKeyDefault: getRSAKey " + e.toString());
            throw e;
        }
        RSAPublicKey rsaKey = new RSAPublicKey(newkey.getEncoded());

        return rsaKey.getKeySize();
    }

    public int getDSAKeyLen(X509Key key) throws Exception {
        // Check DSAKey parameters.
        // size refers to the p parameter.
        DSAPublicKey dsaKey = new DSAPublicKey(key.getEncoded());
        DSAParams keyParams = dsaKey.getParams();
        BigInteger p = keyParams.getP();
        int len = p.bitLength();

        return len;
    }

    /**
     * Populates the request with this policy default.
     */
    @Override
    public void populate(Request request, X509CertInfo info)
            throws EProfileException {
        CertificateX509Key certKey = null;
        String method = "ServerKeygenUserKeyDefault: populate: ";
        logger.debug(method + "begins");
        String errmsg = "";

        // trigger serverSide keygen enrollment
        try {
            String p12passwd = request.getExtDataInString("serverSideKeygenP12Passwd");
            if (p12passwd == null || p12passwd.length() == 0) {
                logger.debug(method + "p12passwd not found");
                throw new EPropertyException(CMS.getUserMessage("CMS_PASSWORD_EMPTY_PASSWORD"));
            }
            request.setExtData("isServerSideKeygen", "true");

            String keyTypeStr = request.getExtDataInString("keyType");
            String keyType = "RSA";
            int keySize = 2048;
            String curveName = "nistp256";

            // Populate the keyType and keySize/keyCurve

            if (keyTypeStr != null && !keyTypeStr.isEmpty()) {
                logger.debug("ServerKeygenUserKeyDefault: populate: keyType in request: " + keyTypeStr);
                keyType = keyTypeStr;
            } else {
                logger.debug("ServerKeygenUserKeyDefault: populate: keyType in request null; default to RSA");
            }

            boolean isEC = false;
            String keySizeCurveStr = request.getExtDataInString("keySize");

            if (keyType.contentEquals("RSA")) {
                if (keySizeCurveStr != null && !keySizeCurveStr.isEmpty()) {
                    logger.debug("ServerKeygenUserKeyDefault: populate: keySize in request: " + keySizeCurveStr);
                    keySize = Integer.parseInt(keySizeCurveStr);
                } else {
                    logger.debug("ServerKeygenUserKeyDefault: populate: keySize in request null;  default to" + keySize);
                }
                // Do things when RSA is selected
            } else if (keyType.contentEquals("EC")) {
                isEC = true;
                // TODO: dmoluguw: Fix the following to generate right Key ECC keys

                if (keySizeCurveStr != null && !keySizeCurveStr.isEmpty()) {
                    logger.debug("ServerKeygenUserKeyDefault: populate: keyCurve in request: " + keySizeCurveStr);
                    curveName = keySizeCurveStr;
                } else {
                    logger.debug("ServerKeygenUserKeyDefault: populate: keySize in request null;  default to" + curveName);
                }
                // Do things when EC is selected
            } else {
                throw new Exception("Unsupported keyType: " + keyType);
            }
            request.setExtData(Request.KEY_GEN_ALGORITHM, keyType);
            if(keyType.contentEquals("RSA")) {
                request.setExtData(Request.KEY_GEN_SIZE, keySize);
            }
            else if (keyType.contentEquals("EC")) {
                // TODO: Check whether Request.KEY_GEN_SIZE can accept string value
                request.setExtData(Request.KEY_GEN_SIZE, curveName);
            }

            /*
             * DO NOT REMOVE
             * currently, it is necessary to  put in a static placeholder fake
             * key here to prevent issue; The fake key will be replaced later
             * once KRA generates the real keys
             *
             * TODO: perhaps find out how to get around not breaking
             * the code without fake keys
             */

            String pubKeyStr = "";
            if (!isEC) {
              switch (keySize) {
                case 1024:
                    pubKeyStr = TEMP_PUBKEY_RSA_1024;
                    break;
                case 2048:
                    pubKeyStr = TEMP_PUBKEY_RSA_2048;
                    break;
                case 3072:
                    pubKeyStr = TEMP_PUBKEY_RSA_3072;
                    break;
                case 4096:
                    pubKeyStr = TEMP_PUBKEY_RSA_4096;
                    break;
                default:
                    errmsg = "unsupported keySize: " + keySize;
                    logger.debug("ServerKeygenUserKeyDefault: populate: " + errmsg);
                    throw new EProfileException(errmsg);
              }
            } else {
              switch (curveName) {
                case "nistp256":
                    pubKeyStr = TEMP_PUBKEY_EC_NISTP256;
                    break;
                case "nistp384":
                    pubKeyStr = TEMP_PUBKEY_EC_NISTP384;
                    break;
                case "nistp521":
                    pubKeyStr = TEMP_PUBKEY_EC_NISTP521;
                    break;
                default:
                    errmsg = "unsupported cureveName: " + curveName;
                    logger.debug("ServerKeygenUserKeyDefault: populate: " + errmsg);
                    throw new EProfileException(errmsg);
              }
            }
            byte[] certKeyData = CryptoUtil.base64Decode(pubKeyStr);
            if (certKeyData != null) {
                certKey = new CertificateX509Key(
                        new ByteArrayInputStream(certKeyData));
            } else {
                logger.debug("ServerKeygenUserKeyDefault: populate: serverKeygen to be implemented ");
            }

            // the param "enableArchival" allows the profile to decide whether
            // to archive the keys or not; By default, it is *false*
            boolean enableArchival = getConfigBoolean(CONFIG_ENABLE_ARCHIVAL);
            //logger.debug(method + "archival enabled: " + enableArchival);
            request.setExtData(Request.SERVER_SIDE_KEYGEN_ENROLL_ENABLE_ARCHIVAL, enableArchival? "true":"false");

            info.set(X509CertInfo.KEY, certKey);
            logger.debug(method + "fake key injected for SSK.");
        } catch (Exception e) {
            logger.debug("ServerKeygenUserKeyDefault: populate " + e.toString());
            throw new EProfileException(e.getMessage());
        }
    }
}
