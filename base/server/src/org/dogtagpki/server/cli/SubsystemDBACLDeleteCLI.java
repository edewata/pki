//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.io.File;
import java.util.Map;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.servlet.csadmin.LDAPConfigurator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystemConfig;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class SubsystemDBACLDeleteCLI extends CommandCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemDBACLDeleteCLI.class);

    public SubsystemDBACLDeleteCLI(CLI parent) {
        super("del", "Delete " + parent.parent.parent.getName().toUpperCase() + " manager ACLs", parent);
    }

    public void createOptions() {
        Option option = new Option(null, "user-id", true, "User ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "user-dn", true, "User DN");
        option.setArgName("DN");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String userID = cmd.getOptionValue("user-id");
        String userDN = cmd.getOptionValue("user-dn");

        if (userID == null && userDN == null) {
            throw new Exception("Missing user ID or DN");
        }

        String catalinaBase = System.getProperty("catalina.base");

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();

        String subsystem = parent.parent.parent.getName();
        String subsystemDir = catalinaBase + File.separator + subsystem;
        String subsystemConfDir = subsystemDir + File.separator + "conf";
        String configFile = subsystemConfDir + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStore(configFile);
        EngineConfig cs = new EngineConfig(storage);
        cs.load();

        LDAPConfig ldapConfig = cs.getInternalDBConfig();
        String instanceId = cs.getInstanceID();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        IPasswordStore passwordStore = IPasswordStore.create(psc);

        LDAPConnectionConfig connConfig = ldapConfig.getConnectionConfig();
        LDAPAuthenticationConfig authConfig = ldapConfig.getAuthenticationConfig();

        LdapConnInfo connInfo = new LdapConnInfo(connConfig);

        LdapAuthInfo authInfo = new LdapAuthInfo();
        authInfo.setPasswordStore(passwordStore);
        authInfo.init(
                authConfig,
                connInfo.getHost(),
                connInfo.getPort(),
                connInfo.getSecure());

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PKISocketFactory socketFactory;
        if (authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
            socketFactory = new PKISocketFactory(authInfo.getClientCertNickname());
        } else {
            socketFactory = new PKISocketFactory(connInfo.getSecure());
        }
        socketFactory.init(socketConfig);

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);
        LDAPConfigurator ldapConfigurator = new LDAPConfigurator(conn, ldapConfig, instanceId);

        UGSubsystemConfig ugConfig = cs.getUGSubsystemConfig();
        UGSubsystem ugSubsystem = new UGSubsystem();

        try {
            Map<String, String> params = ldapConfigurator.getParams();

            if (userID != null) {
                ugSubsystem.init(socketConfig, ugConfig, passwordStore);
                userDN = "uid=" + LDAPUtil.escapeRDNValue(userID) + "," + ugSubsystem.getUserBaseDN();
            }

            params.put("dbuser", userDN);

            logger.info("Deleting ACLs for " + userDN);

            File file = new File("/usr/share/pki/server/conf/manager-acl-del.ldif");
            File tmpFile = File.createTempFile("manager-acl-del-", ".ldif");

            try {
                ldapConfigurator.customizeFile(file, tmpFile, params);
                ldapConfigurator.importLDIF(tmpFile, true);
            } finally {
                tmpFile.delete();
            }

        } finally {
            ugSubsystem.shutdown();
            conn.disconnect();
        }
    }
}
