//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.codec.binary.Hex;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.nss.NSSDatabase;
import org.mozilla.jss.crypto.CryptoToken;

import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class NSSKeyRemoveCLI extends CommandCLI {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSKeyRemoveCLI.class);

    public NSSKeyRemoveCLI(NSSKeyCLI nssKeyCLI) {
        super("del", "Remove key", nssKeyCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "key-id", true, "Key ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "key-id-file", true, "File containing key ID");
        option.setArgName("path");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String keyID = cmd.getOptionValue("key-id");
        String keyIDFile = cmd.getOptionValue("key-id-file");

        if (keyID == null && keyIDFile != null) {
            // load key ID from file
            keyID = Files.readString(Paths.get(keyIDFile)).strip();
        }

        if (keyID == null) {
            throw new CLIException("Missing key ID");
        }

        if (keyID.startsWith("0x")) keyID = keyID.substring(2);
        if (keyID.length() % 2 == 1) keyID = "0" + keyID;

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        String tokenName = mainCLI.getConfig().getTokenName();
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

        NSSDatabase nssdb = mainCLI.getNSSDatabase();
        KeyPair keyPair = nssdb.loadKeyPair(token, Hex.decodeHex(keyID));

        CryptoUtil.deleteKeyPair(keyPair);
    }
}
