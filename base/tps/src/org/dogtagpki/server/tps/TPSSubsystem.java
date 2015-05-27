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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.tps;

import org.dogtagpki.server.tps.authentication.AuthenticationManager;
import org.dogtagpki.server.tps.cms.ConnectionManager;
import org.dogtagpki.server.tps.config.AuthenticatorDatabase;
import org.dogtagpki.server.tps.config.ConfigDatabase;
import org.dogtagpki.server.tps.config.ConnectorDatabase;
import org.dogtagpki.server.tps.config.ProfileDatabase;
import org.dogtagpki.server.tps.config.ProfileMappingDatabase;
import org.dogtagpki.server.tps.dbs.ActivityDatabase;
import org.dogtagpki.server.tps.dbs.TPSCertDatabase;
import org.dogtagpki.server.tps.dbs.TokenDatabase;
import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.server.tps.mapping.MappingResolverManager;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.TokenException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.cmscore.dbs.DBSubsystem;

/**
 * @author Endi S. Dewata <edewata@redhat.com>
 */
public class TPSSubsystem implements IAuthority, ISubsystem {

    public final static String ID = "tps";

    public ILogger logger = CMS.getLogger();

    public String id;
    public String nickname;
    public ISubsystem owner;
    public IConfigStore config;

    public ActivityDatabase activityDatabase;
    public AuthenticatorDatabase authenticatorDatabase;
    public TPSCertDatabase certDatabase;
    public ConfigDatabase configDatabase;
    public ConnectorDatabase connectorDatabase;
    public ProfileDatabase profileDatabase;
    public ProfileMappingDatabase profileMappingDatabase;
    public TokenDatabase tokenDatabase;
    public ConnectionManager connManager;
    public AuthenticationManager authManager;
    public MappingResolverManager mappingResolverManager;
    public TPSEngine engine;
    public TPSTokendb tdb;

    @Override
    public String getId() {
        return id;
    }

    @Override
    public void setId(String id) throws EBaseException {
        this.id = id;
    }

    @Override
    public void init(ISubsystem owner, IConfigStore config) throws EBaseException {
        this.owner = owner;
        this.config = config;

        IDBSubsystem dbSubsystem = DBSubsystem.getInstance();
        IConfigStore cs = CMS.getConfigStore();

        String activityDatabaseDN = cs.getString("tokendb.activityBaseDN");
        activityDatabase = new ActivityDatabase(dbSubsystem, activityDatabaseDN);

        String certDatabaseDN = cs.getString("tokendb.certBaseDN");
        certDatabase = new TPSCertDatabase(dbSubsystem, certDatabaseDN);

        String tokenDatabaseDN = cs.getString("tokendb.baseDN");
        tokenDatabase = new TokenDatabase(dbSubsystem, tokenDatabaseDN);

        configDatabase = new ConfigDatabase();
        authenticatorDatabase = new AuthenticatorDatabase();
        connectorDatabase = new ConnectorDatabase();
        profileDatabase = new ProfileDatabase();
        profileMappingDatabase = new ProfileMappingDatabase();
        tdb = new TPSTokendb(this);

        engine = new TPSEngine();
        engine.init();

    }

    @Override
    public void startup() throws EBaseException {
        CMS.debug("TPSSubsystem: startup() begins");
        connManager = new ConnectionManager();
        connManager.initConnectors();
        authManager = new AuthenticationManager();
        authManager.initAuthInstances();
        mappingResolverManager = new MappingResolverManager();
        mappingResolverManager.initMappingResolverInstances();
        CMS.debug("TPSSubsystem: startup() ends.");
    }

    @Override
    public void shutdown() {
    }

    @Override
    public IConfigStore getConfigStore() {
        return config;
    }

    @Override
    public IRequestQueue getRequestQueue() {
        return null;
    }

    @Override
    public void registerRequestListener(IRequestListener listener) {
    }

    @Override
    public void registerPendingListener(IRequestListener listener) {
    }

    @Override
    public void log(int level, String msg) {
        logger.log(ILogger.EV_SYSTEM, ILogger.S_TPS, level, msg);
    }

    @Override
    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
    }

    @Override
    public String getOfficialName() {
        return "tps";
    }

    public ActivityDatabase getActivityDatabase() {
        return activityDatabase;
    }

    public AuthenticatorDatabase getAuthenticatorDatabase() {
        return authenticatorDatabase;
    }

    public TPSCertDatabase getCertDatabase() {
        return certDatabase;
    }

    public ConfigDatabase getConfigDatabase() {
        return configDatabase;
    }

    public ConnectorDatabase getConnectorDatabase() {
        return connectorDatabase;
    }

    public ProfileDatabase getProfileDatabase() {
        return profileDatabase;
    }

    public ProfileMappingDatabase getProfileMappingDatabase() {
        return profileMappingDatabase;
    }

    public TokenDatabase getTokenDatabase() {
        return tokenDatabase;
    }

    public ConnectionManager getConnectionManager() {
        return connManager;
    }

    public AuthenticationManager getAuthenticationManager() {
        return authManager;
    }

    public MappingResolverManager getMappingResolverManager() {
        return mappingResolverManager;
    }

    public TPSTokendb getTokendb() {
        return tdb;
    }

    public org.mozilla.jss.crypto.X509Certificate getSubsystemCert() throws EBaseException, NotInitializedException,
            ObjectNotFoundException, TokenException {
        IConfigStore cs = CMS.getConfigStore();
        String nickname = cs.getString("tps.subsystem.nickname", "");
        String tokenname = cs.getString("tps.subsystem.tokenname", "");
        if (!tokenname.equals("internal") && !tokenname.equals("Internal Key Storage Token"))
            nickname = tokenname + ":" + nickname;

        CryptoManager cm = CryptoManager.getInstance();
        return cm.findCertByNickname(nickname);
    }

    public TPSEngine getEngine() {
        return engine;
    }
}
