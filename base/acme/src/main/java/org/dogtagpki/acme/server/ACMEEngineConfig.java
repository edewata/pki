//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URL;
import java.util.Map.Entry;
import java.util.Properties;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ACMEEngineConfig implements JSONSerializer {

    private Boolean enabled = true;
    private URL baseURL;
    private Boolean noncesPersistent;

    @JsonProperty("policy")
    private ACMEPolicyConfig policyConfig = new ACMEPolicyConfig();

    public Boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public URL getBaseURL() {
        return baseURL;
    }

    public void setBaseURL(URL baseURL) {
        this.baseURL = baseURL;
    }

    public Boolean getNoncesPersistent() {
        return noncesPersistent;
    }

    public void setNoncePersistent(Boolean noncesPersistent) {
        this.noncesPersistent = noncesPersistent;
    }

    public ACMEPolicyConfig getPolicyConfig() {
        return policyConfig;
    }

    public void setPolicyConfig(ACMEPolicyConfig wildcard) {
        this.policyConfig = wildcard;
    }

    public static ACMEEngineConfig fromProperties(Properties props) throws Exception {

        ACMEEngineConfig config = new ACMEEngineConfig();

        for (Entry<Object, Object> entry : props.entrySet()) {

            String key = entry.getKey().toString();
            String value = entry.getValue().toString();

            if (key.equals("enabled")) {
                config.setEnabled(Boolean.valueOf(value));

            } else if (key.equals("baseURL")) {
                config.setBaseURL(new URL(value));

            } else if (key.equals("nonces.persistent")) {
                config.setNoncePersistent(Boolean.valueOf(value));

            } else if (key.startsWith("policy.")) {

                String policyKey = key.substring(7);

                ACMEPolicyConfig policyConfig = config.getPolicyConfig();
                policyConfig.setProperty(policyKey, value);
            }
        }

        return config;
    }

    @Override
    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        ACMEEngineConfig engineConfig = new ACMEEngineConfig();
        System.out.println(engineConfig);
    }
}
