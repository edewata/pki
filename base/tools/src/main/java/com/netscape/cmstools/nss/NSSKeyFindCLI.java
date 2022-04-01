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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.codec.binary.Hex;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.X509Certificate;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyInfo;
import com.netscape.certsrv.key.KeyInfoCollection;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author Endi S. Dewata
 */
public class NSSKeyFindCLI extends CommandCLI {

    public NSSKeyCLI keyCLI;

    public NSSKeyFindCLI(NSSKeyCLI keyCLI) {
        super("find", "Find keys in NSS database", keyCLI);
        this.keyCLI = keyCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "nickname", true, "Certificate nickname");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option(null, "output-format", true, "Output format: text (default), json.");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        String nickname = cmd.getOptionValue("nickname");

        List<PrivateKey> privateKeys;

        if (nickname != null) {
            CryptoManager cm = CryptoManager.getInstance();
            privateKeys = new ArrayList<>();
            for (X509Certificate cert : cm.findCertsByNickname(nickname)) {
                try {
                    PrivateKey privateKey = cm.findPrivKeyByCert(cert);
                    privateKeys.add(privateKey);
                } catch (ObjectNotFoundException e) {
                    // cert doesn't have a key, skip
                }
            }

        } else {
            String tokenName = getConfig().getTokenName();
            CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
            CryptoStore cryptoStore = token.getCryptoStore();
            privateKeys = Arrays.asList(cryptoStore.getPrivateKeys());
        }

        KeyInfoCollection keyInfoCollection = new KeyInfoCollection();
        keyInfoCollection.setTotal(privateKeys.size());

        for (PrivateKey privateKey : privateKeys) {
            KeyInfo keyInfo = new KeyInfo();

            String keyID = Hex.encodeHexString(privateKey.getUniqueID());
            if (keyID.length() % 2 == 1) keyID = "0" + keyID;
            keyID = "0x" + keyID;

            keyInfo.setKeyId(new KeyId(keyID));
            keyInfo.setAlgorithm(privateKey.getAlgorithm());
            keyInfoCollection.addEntry(keyInfo);
        }

        String outputFormat = cmd.getOptionValue("output-format", "text");

        if (outputFormat.equalsIgnoreCase("json")) {
            System.out.println(keyInfoCollection.toJSON());

        } else if (outputFormat.equalsIgnoreCase("text")) {
            boolean first = true;

            for (KeyInfo keyInfo : keyInfoCollection.getEntries()) {

                if (first) {
                    first = false;
                } else {
                    System.out.println();
                }

                NSSKeyCLI.printKeyInfo(keyInfo);
            }

        } else {
            throw new Exception("Unsupported output format: " + outputFormat);
        }
    }
}
