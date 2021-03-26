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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.authentication;

import org.dogtagpki.server.authentication.AuthManagerProxy;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.authentication.CMCAuth;

public class CAAuthSubsystem extends AuthSubsystem {

    /**
     * Constant for CMC authentication plugin ID.
     */
    public final static String CMCAUTH_PLUGIN_ID = "CMCAuth";

    /**
     * Constant for CMC authentication manager ID.
     */
    public final static String CMCAUTH_AUTHMGR_ID = "CMCAuth";

    /**
     * Constant for CMC user-signed authentication manager ID.
     */
    public final static String CMC_USER_SIGNED_AUTH_AUTHMGR_ID = "CMCUserSignedAuth";

    public CAAuthSubsystem() {
    }

    public void loadAuthManagers() throws EBaseException {

        super.loadAuthManagers();

        logger.info("AuthSubsystem: Loading auth manager " + CMCAUTH_AUTHMGR_ID);

        CMCAuth cmcAuth = new CMCAuth();
        cmcAuth.setAuthenticationConfig(mConfig);
        cmcAuth.init(CMCAUTH_AUTHMGR_ID, CMCAUTH_PLUGIN_ID, null);
        mAuthMgrInsts.put(CMCAUTH_AUTHMGR_ID, new AuthManagerProxy(true, cmcAuth));
    }
}
