//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

/**
 * @author Endi S. Dewata
 */
@ApplicationPath("")
public class ACMEApplication extends Application {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEApplication.class);

    public ACMEApplication() {
        logger.info("Initializing ACMEApplication");
    }
}
