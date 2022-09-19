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
package com.netscape.cmscore.dbs;

import java.math.BigInteger;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;

import com.netscape.ca.CRLIssuingPoint;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.certdb.CertId;

import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPSearchResults;

public class RetrieveModificationsTask implements Runnable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RetrieveModificationsTask.class);

    CertificateRepository repository;

    DBSSession session;
    LDAPSearchResults results;

    ScheduledExecutorService executorService;

    public RetrieveModificationsTask(CertificateRepository repository) {
        this.repository = repository;

        executorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                return new Thread(r, "RetrieveModificationsTask");
            }
        });
    }

    public void start() {

        // schedule task to run immediately
        executorService.schedule(this, 0, TimeUnit.MINUTES);
    }

    public void connect() throws EBaseException {

        if (session != null) return;

        CAEngine engine = CAEngine.getInstance();
        DBSubsystem dbSubsystem = engine.getDBSubsystem();

        try {
            session = dbSubsystem.createSession();
            results = repository.searchForModifiedCertificateRecords(session);

        } catch (EBaseException e) {
            close(); // avoid leaks
            throw e;
        }
    }

    /**
     * Retrieves modified certificate records.
     *
     * @param entry LDAPEntry with modified data
     */
    public void retrieveModifications(LDAPEntry entry) {

        if (entry == null) {
            logger.warn("Missing LDAP entry");
            return;
        }

        logger.info("RetrieveModificationsTask: dn: " + entry.getDN());

        CAEngine engine = CAEngine.getInstance();
        DBSubsystem dbSubsystem = engine.getDBSubsystem();

        LDAPAttributeSet entryAttrs = entry.getAttributeSet();
        CertRecord certRecord = null;

        try {
            certRecord = (CertRecord) dbSubsystem.getRegistry().createObject(entryAttrs);
        } catch (Exception e) {
            logger.warn("Unable to create certificate record: " + e.getMessage(), e);
        }

        if (certRecord == null) {
            logger.warn("Unable to create certificate record");
            return;
        }

        BigInteger serialNumber = certRecord.getSerialNumber();
        CertId certID = new CertId(serialNumber);
        logger.info("RetrieveModificationsTask: - serial number: " + certID.toHexString());

        String status = certRecord.getStatus();
        logger.info("RetrieveModificationsTask: - status: " + status);

        if (status == null) {
            logger.warn("Missing certificate status");
            return;
        }

        if (!status.equals(CertRecord.STATUS_VALID) && !status.equals(CertRecord.STATUS_REVOKED)) {
            return;
        }

        for (CRLIssuingPoint ip : engine.getCRLIssuingPoints()) {

            if (ip == null) {
                logger.warn("Missing CRL issuing point");
                continue;
            }

            if (!status.equals(CertRecord.STATUS_REVOKED)) {
                logger.info("RetrieveModificationsTask: Unrevoking cert " + certID.toHexString());
                ip.addUnrevokedCert(certRecord.getSerialNumber());
                continue;
            }

            logger.info("RetrieveModificationsTask: Revoking cert " + certID.toHexString());

            RevocationInfo rInfo = certRecord.getRevocationInfo();
            if (rInfo == null) {
                logger.warn("Missing revocation information");
                continue;
            }

            RevokedCertImpl revokedCert = new RevokedCertImpl(
                    certRecord.getSerialNumber(),
                    rInfo.getRevocationDate(),
                    rInfo.getCRLEntryExtensions());

            ip.addRevokedCert(certRecord.getSerialNumber(), revokedCert);
        }
    }

    public void close() {

        if (session == null) return;

        // make sure the search is abandoned
        if (results != null) try { session.abandon(results); } catch (Exception e) { e.printStackTrace(); }

        // close session
        try { session.close(); } catch (Exception e) { e.printStackTrace(); }

        session = null;
    }

    @Override
    public void run() {
        try {
            // make sure it's connected
            connect();

            // results.hasMoreElements() will block until next result becomes available
            // or return false if the search is abandoned or the connection is closed

            logger.info("RetrieveModificationsTask: Listening to cert database modifications");

            if (results.hasMoreElements()) {
                LDAPEntry entry = results.next();

                logger.info("RetrieveModificationsTask: Processing " + entry.getDN());
                retrieveModifications(entry);
                logger.info("RetrieveModificationsTask: Done processing " + entry.getDN());

                // wait for next result immediately
                executorService.schedule(this, 0, TimeUnit.MINUTES);

            } else {
                if (executorService.isShutdown()) {
                    logger.info("RetrieveModificationsTask: Task has been shutdown");

                } else {
                    logger.info("RetrieveModificationsTask: Persistence search ended");
                    close();

                    logger.info("RetrieveModificationsTask: Retrying in 1 minute");
                    executorService.schedule(this, 1, TimeUnit.MINUTES);
                }
            }

        } catch (Exception e) {
            logger.warn("Unable to process cert database modification: " + e.getMessage(), e);
            close();

            logger.warn("Retrying in 1 minute");
            executorService.schedule(this, 1, TimeUnit.MINUTES);
        }
    }

    public void stop() {
        executorService.shutdown();
        close();
    }
}
