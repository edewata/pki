//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.dbs.Repository;
import com.netscape.cmscore.dbs.Repository.IDGenerator;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;
import java.math.BigInteger;
import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;
import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.util.logging.PKILogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public abstract class SubsystemIdGeneratorUpdateCLI extends SubsystemCLI {
    private static final Logger logger = LoggerFactory.getLogger(SubsystemIdGeneratorUpdateCLI.class);
    protected IDGenerator idGenerator;

    public SubsystemIdGeneratorUpdateCLI(CLI parent) {
        super("update", "Update " + parent.getParent().getParent().getName().toUpperCase() + " range generator", parent);
    }
    @Override
    public void createOptions() {
        options.addOption("t", "type", true, "Generator type to update.");
        options.addOption("r", "range", true, "Name of the ranges entry in DS.");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {
        if (!cmd.hasOption("type")) {
            throw new Exception("Missing generator type.");
        }
        IDGenerator generator = IDGenerator.fromString(cmd.getOptionValue("type"));
        
        String newRangesName = generator == IDGenerator.LEGACY_2 ? "ranges_v2" : "ranges_new";
        if (cmd.hasOption("range")) {
            newRangesName = cmd.getOptionValue("range");
        }

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.LogLevel.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(PKILogger.LogLevel.INFO);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("Missing generator");
        }
        String generatorAtttirbute = cmdArgs[0];

        initializeTomcatJSS();
        String subsystem = parent.getParent().getParent().getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        LDAPConfig ldapConfig = cs.getInternalDBConfig();
        String baseDN = ldapConfig.getBaseDN();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = CMS.createPasswordStore(psc);

        LDAPConnectionConfig connConfig = ldapConfig.getConnectionConfig();

        LdapConnInfo connInfo = new LdapConnInfo(connConfig);
        LdapAuthInfo authInfo = getAuthInfo(passwordStore, connInfo, ldapConfig);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PKISocketFactory socketFactory = new PKISocketFactory();
        socketFactory.setSecure(connInfo.getSecure());
        if (authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
            socketFactory.setClientCertNickname(authInfo.getClientCertNickname());
        }
        socketFactory.init(socketConfig);

        DatabaseConfig dbConfig = cs.getDatabaseConfig();
        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);
        try {
            if (generatorAtttirbute.equals("cert")){
                updateSerialNumberRangeGenerator(
                        conn,
                        dbConfig,
                        baseDN,
                        newRangesName,
                        generator,
                        cs.getHostname(),
                        getSecurePort(cs));
                cs.commit(false);
            } else if (generatorAtttirbute.equals("request")) {
                updateRequestNumberRangeGenerator(
                        conn,
                        dbConfig,
                        baseDN,
                        newRangesName,
                        generator,
                        cs.getHostname(),
                        getSecurePort(cs));
                cs.commit(false);
            } else {
                throw new EBaseException("Generator for " + generatorAtttirbute + " not supported.");            
            }
        } finally {
            conn.disconnect();
        }

    }

    protected void updateSerialNumberRangeGenerator(LdapBoundConnection conn,
            DatabaseConfig dbConfig, String baseDN, String newRangesName,
            IDGenerator newGenerator, String hostName, String securePort) throws Exception {
        
        if (newGenerator == IDGenerator.RANDOM && idGenerator != IDGenerator.RANDOM) {
            logger.debug("Remove serial ranges from configuration");
            dbConfig.remove(DatabaseConfig.MIN_SERIAL_NUMBER);
            dbConfig.remove(DatabaseConfig.MAX_SERIAL_NUMBER);
            dbConfig.remove(DatabaseConfig.SERIAL_INCREMENT);
            dbConfig.remove(DatabaseConfig.SERIAL_LOW_WATER_MARK);
            dbConfig.remove(DatabaseConfig.SERIAL_CLONE_TRANSFER_NUMBER);
            dbConfig.remove(DatabaseConfig.SERIAL_RANGE_DN);
            return;
        }

        if (newGenerator == IDGenerator.LEGACY_2 && idGenerator == IDGenerator.LEGACY) {
            logger.debug("SubsystemIdGeneratorUpdateCLI: Updating ranges entry to hex format");

            String rangeDN = dbConfig.getSerialRangeDN() + "," + baseDN;
            String newRangeDN = createRangesEntry(conn, "certificateRepository", newRangesName, baseDN);
            dbConfig.setSerialRangeDN(newRangeDN);
            newRangeDN = newRangeDN + "," + baseDN;

            String serialIncrement = dbConfig.getSerialIncrement();
            dbConfig.setSerialIncrement("0x" + serialIncrement);
            BigInteger incremennt = new BigInteger(serialIncrement, 16);

            String serialLowWaterMark = dbConfig.getSerialLowWaterMark();
            dbConfig.setSerialLowWaterMark("0x" + serialLowWaterMark);

            String serialCloneTransfer = dbConfig.getSerialCloneTransferNumber();
            dbConfig.setSerialCloneTransferNumber("0x" + serialCloneTransfer);

            String beginSerialNumber = dbConfig.getBeginSerialNumber();
            dbConfig.setBeginSerialNumber("0x" + beginSerialNumber);
            BigInteger beginSerialNo = new BigInteger(beginSerialNumber, 16);
            String endSerialNumber = dbConfig.getEndSerialNumber();
            BigInteger endSerialNo = new BigInteger(endSerialNumber, 16);
            if (endSerialNo.equals(beginSerialNo.add(incremennt).subtract(BigInteger.ONE))){
                try {
                    LDAPEntry entrySerial = conn.read("cn=" + beginSerialNumber+"," + rangeDN);
                    LDAPAttribute attrEnd = entrySerial.getAttribute("endRange");
                    if (attrEnd != null) {
                        endSerialNumber = attrEnd.getStringValues().nextElement();
                    }
                } catch (LDAPException ldae) {
                    if (ldae.getLDAPResultCode() == 32) {
                        logger.debug("No range available, using config values");
                    } else {
                        logger.error("LDAP error: " + ldae.getMessage(), ldae);
                        return;
                    }

                }
            }
            dbConfig.setEndSerialNumber("0x" + endSerialNumber);

            String nextBeginSerial = dbConfig.getNextBeginSerialNumber();
            String nextEndSerial = dbConfig.getNextEndSerialNumber();
            if (nextBeginSerial != null && !nextBeginSerial.equals("-1")) {
                dbConfig.setNextBeginSerialNumber("0x" + nextBeginSerial);

                try {
                    LDAPEntry entryNextSerial = conn.read("cn=" + nextBeginSerial + "," + rangeDN);
                    LDAPAttribute attrNextEnd = entryNextSerial.getAttribute("endRange");
                    if (attrNextEnd != null) {
                        nextEndSerial = attrNextEnd.getStringValues().nextElement();
                    }
                } catch (LDAPException ldae) {
                    if (ldae.getLDAPResultCode() == 32) {
                        logger.debug("No range available, using config vaules");
                    } else {
                        logger.error("LDAP error", ldae);
                        return;
                    }

                }
                dbConfig.setNextEndSerialNumber("0x" + nextEndSerial);
                endSerialNumber = nextEndSerial;
            }
            updateCertificateRanges(dbConfig, conn, baseDN, rangeDN, newRangeDN, endSerialNumber, hostName, securePort);
            return;
        }
        throw new EBaseException("Update to " + newGenerator + " not supported");
    }

    protected void updateRequestNumberRangeGenerator(LdapBoundConnection conn,
            DatabaseConfig dbConfig, String baseDN, String newRangesName, IDGenerator newGenerator,
            String hostName, String securePort) throws Exception {
        
        String value = dbConfig.getString(
                RequestRepository.PROP_REQUEST_ID_GENERATOR,
                RequestRepository.DEFAULT_REQUEST_ID_GENERATOR);
        idGenerator = IDGenerator.fromString(value);

        if (newGenerator == IDGenerator.RANDOM && idGenerator != IDGenerator.RANDOM) {
            logger.debug("Remove request ranges from configuration");
            dbConfig.remove(DatabaseConfig.MIN_REQUEST_NUMBER);
            dbConfig.remove(DatabaseConfig.MAX_REQUEST_NUMBER);
            dbConfig.remove(DatabaseConfig.REQUEST_INCREMENT);
            dbConfig.remove(DatabaseConfig.REQUEST_LOW_WATER_MARK);
            dbConfig.remove(DatabaseConfig.REQUEST_CLONE_TRANSFER_NUMBER);
            dbConfig.remove(DatabaseConfig.REQUEST_RANGE_DN);
            dbConfig.put(RequestRepository.PROP_REQUEST_ID_GENERATOR, newGenerator.toString());
            dbConfig.put(RequestRepository.PROP_REQUEST_ID_LENGTH, "128");
            return;
        }
        if (newGenerator == IDGenerator.LEGACY_2 && idGenerator == IDGenerator.LEGACY) {
            dbConfig.put(RequestRepository.PROP_REQUEST_ID_GENERATOR, newGenerator.toString());
            dbConfig.put(RequestRepository.PROP_REQUEST_ID_RADIX, Integer.toString(Repository.DEC));
            String rangeDN = dbConfig.getRequestRangeDN() + "," + baseDN;

            String newRangeDN = createRangesEntry(conn, "requests", newRangesName, baseDN);
            dbConfig.setRequestRangeDN(newRangeDN);
            newRangeDN = newRangeDN + "," + baseDN;

            updateRequestRanges(conn, rangeDN, newRangeDN, hostName, securePort);
            return;
        }
        throw new EBaseException("Update to " + newGenerator + " not supported");
    }
    
    private void updateCertificateRanges(DatabaseConfig dbConfig, LdapBoundConnection conn,
            String baseDN, String rangeDN, String newRangeDN, String configEndSerialNumber,
            String hostName, String securePort) throws Exception{
        LDAPSearchResults instanceRanges = conn.search(rangeDN, LDAPv3.SCOPE_SUB, "(&(objectClass=pkiRange)(host= " +
                    hostName + ")(SecurePort=" + securePort + "))", null, false);
        
        // update all ranges associated to the CA to update to decimal
        while (instanceRanges.hasMoreElements()) {
            LDAPEntry entry = instanceRanges.next();
            String beginRange = entry.getAttribute("beginRange").getStringValues().nextElement();
            BigInteger beginRangeNo = new BigInteger(beginRange, 16);
            String endRange = entry.getAttribute("endRange").getStringValues().nextElement();
            BigInteger endRangeNo = new BigInteger(endRange, 16);
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectClass", "top"));
            attrs.add(new LDAPAttribute("objectClass", "pkiRange"));

            // store beginRange as decimal
            attrs.add(new LDAPAttribute("beginRange", beginRangeNo.toString()));

            // store endRange as decimal
            attrs.add(new LDAPAttribute("endRange", endRangeNo.toString()));

            attrs.add(new LDAPAttribute("cn", beginRangeNo.toString()));
            attrs.add(new LDAPAttribute("host", hostName));
            attrs.add(new LDAPAttribute("securePort", securePort));

            String dn = "cn=" + beginRangeNo.toString() + "," + newRangeDN;
            LDAPEntry rangeEntry = new LDAPEntry(dn, attrs);
            logger.info("SubsystemRangeGeneratorUpdateCLI.updateRanges: Adding entry " + dn);
            conn.add(rangeEntry);
        }

        LDAPSearchResults ranges = conn.search(newRangeDN, LDAPv3.SCOPE_SUB, "(objectClass=pkiRange)", null, false);

        BigInteger lastUsedSerial = BigInteger.ZERO;
        boolean nextRangeToUpdate = true;
        // Search for the last range entry. If it is associated to the CA to update or ranges are not defined
        // then the nextRange is         
        while (ranges.hasMoreElements()) {
            LDAPEntry entry = ranges.next();
            String endRange = entry.getAttribute("endRange").getStringValues().nextElement();
            String host = entry.getAttribute("host").getStringValues().nextElement();
            String port = entry.getAttribute("securePort").getStringValues().nextElement();
            BigInteger next = new BigInteger(endRange);
            if (lastUsedSerial.compareTo(next) < 0) {
                lastUsedSerial = next;
                nextRangeToUpdate = host.equals(hostName) && port.equals(securePort);
                
            }
        }

        if (nextRangeToUpdate) {
            // nextRange is updated using last range entry or, if no ranges, the configured endSerialNumber
            if (lastUsedSerial == BigInteger.ZERO) {
                lastUsedSerial = new BigInteger(configEndSerialNumber, 16);
            }
            BigInteger nextSerialNumber = lastUsedSerial.add(BigInteger.ONE);
            String serialDN = dbConfig.getSerialDN() + "," + baseDN;
            // store nextRange as decimal
            LDAPAttribute attrSerialNextRange = new LDAPAttribute("nextRange", nextSerialNumber.toString());

            LDAPModification serialmod = new LDAPModification(LDAPModification.REPLACE, attrSerialNextRange);

            conn.modify(serialDN, serialmod);
        }
    }
    private void updateRequestRanges(LdapBoundConnection conn, String rangeDN, String newRangeDN,
            String hostName, String securePort) throws Exception{
        LDAPSearchResults instanceRanges = conn.search(rangeDN, LDAPv3.SCOPE_SUB, "(&(objectClass=pkiRange)(host= " +
                    hostName + ")(SecurePort=" + securePort + "))", null, false);
        
        // update all ranges associated to the CA to update to decimal
        while (instanceRanges.hasMoreElements()) {
            LDAPEntry entry = instanceRanges.next();
            String beginRange = entry.getAttribute("beginRange").getStringValues().nextElement();
            String endRange = entry.getAttribute("endRange").getStringValues().nextElement();
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectClass", "top"));
            attrs.add(new LDAPAttribute("objectClass", "pkiRange"));

            // store beginRange as decimal
            attrs.add(new LDAPAttribute("beginRange", beginRange));

            // store endRange as decimal
            attrs.add(new LDAPAttribute("endRange", endRange));

            attrs.add(new LDAPAttribute("cn", beginRange));
            attrs.add(new LDAPAttribute("host", hostName));
            attrs.add(new LDAPAttribute("securePort", securePort));

            String dn = "cn=" + beginRange + "," + newRangeDN;
            LDAPEntry rangeEntry = new LDAPEntry(dn, attrs);
            logger.info("SubsystemRangeGeneratorUpdateCLI.updateRanges: Adding entry " + dn);
            conn.add(rangeEntry);
        }
    }
    
    private String createRangesEntry(LdapBoundConnection conn, String newRangeObject, String ranges, String baseDN) throws Exception {
        String baseRanges =  "ou=" + ranges;
        String baseRangesDN = baseRanges + "," + baseDN;
        try {
            logger.debug("SubsystemRangeGeneratorUpdateCLI: Create ranges entry: {}", baseRangesDN);
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectClass", "top"));
            attrs.add(new LDAPAttribute("objectClass", "organizationalUnit"));
            attrs.add(new LDAPAttribute("ou", ranges));
            LDAPEntry rangesEntry = new LDAPEntry(baseRangesDN, attrs);
            conn.add(rangesEntry);
        } catch (LDAPException ldae) {
            if (ldae.getLDAPResultCode() != 68) {
                throw new EBaseException("Impossible create ranges object: " + ldae.getMessage(), ldae);
            }
            logger.debug("SubsystemRangeGeneratorUpdateCLI: entry {} already exist", baseRangesDN);
        }
        
        String newRangeEntry = "ou=" + newRangeObject + "," + baseRanges;
        String newRangeEntryDN = newRangeEntry + "," + baseDN;
        logger.debug("SubsystemRangeGeneratorUpdateCLI: Create range entry: {}", newRangeEntryDN);
        try {
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectClass", "top"));
            attrs.add(new LDAPAttribute("objectClass", "organizationalUnit"));
            attrs.add(new LDAPAttribute("ou", newRangeObject));
            LDAPEntry rangeEntry = new LDAPEntry(newRangeEntryDN, attrs);
            conn.add(rangeEntry);
        } catch (LDAPException ldae) {
            if (ldae.getLDAPResultCode() != 68) {
                throw new EBaseException("Impossible access object in ranges: " + ldae.getMessage(), ldae);
            }
            logger.debug("SubsystemRangeGeneratorUpdateCLI: entry {} already exist", baseRangesDN);            
        }
        return newRangeEntry;
    }
}