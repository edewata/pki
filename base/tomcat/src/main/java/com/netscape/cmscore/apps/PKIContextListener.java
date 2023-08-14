//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.apps;

import org.apache.catalina.Context;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.apache.catalina.Realm;

public class PKIContextListener implements LifecycleListener {

    private static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIContextListener.class);

    @Override
    public void lifecycleEvent(LifecycleEvent event) {

        String type = event.getType();
        logger.info("PKIContextLifecycle: type: " + type);

        Lifecycle lifecycle = event.getLifecycle();
        logger.info("PKIContextLifecycle: lifecycle: " + lifecycle);
        logger.info("PKIContextLifecycle: lifecycle: " + lifecycle.getClass().getName());

        if (type.equals(Lifecycle.AFTER_START_EVENT)) {
            afterStart((Context) lifecycle);
        }
    }

    public void afterStart(Context context) {
        Realm realm = context.getRealm();
        logger.info("PKIContextLifecycle: realm: " + realm);
        logger.info("PKIContextLifecycle: realm: " + realm.getClass().getName());
    }
}
