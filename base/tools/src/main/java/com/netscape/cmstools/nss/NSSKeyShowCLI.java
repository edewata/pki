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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.nss;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyInfo;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Endi S. Dewata
 */
public class NSSKeyShowCLI extends CommandCLI {

    public NSSKeyCLI keyCLI;

    public NSSKeyShowCLI(NSSKeyCLI keyCLI) {
        super("show", "Show key in NSS database", keyCLI);
        this.keyCLI = keyCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <key ID>", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "output-format", true, "Output format: text (default), json.");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing key ID");
        }

        String keyID = cmdArgs[0];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        String tokenName = getConfig().getTokenName();
        CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
        CryptoStore cryptoStore = token.getCryptoStore();

        logger.info("Private keys:");
        PrivateKey privateKey = null;

        for (PrivateKey privKey : cryptoStore.getPrivateKeys()) {
            String id = "0x" + Utils.HexEncode(privKey.getUniqueID());
            logger.info("- " + id);

            if (keyID.equals(id)) {
                privateKey = privKey;
                break;
            }
        }

        if (privateKey == null) {
            throw new Exception("Key not found");
        }

        logger.info("Found key " + keyID);

        KeyInfo keyInfo = new KeyInfo();
        keyInfo.setKeyId(new KeyId(keyID));
        keyInfo.setAlgorithm(privateKey.getAlgorithm());

        String outputFormat = cmd.getOptionValue("output-format", "text");

        if (outputFormat.equalsIgnoreCase("json")) {
            System.out.println(keyInfo.toJSON());

        } else if (outputFormat.equalsIgnoreCase("text")) {
            NSSKeyCLI.printKeyInfo(keyInfo);

        } else {
            throw new Exception("Unsupported output format: " + outputFormat);
        }
    }
}
