//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.io.PrintWriter;

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyInfo;

public class NSSKeyCLI extends CLI {

    public NSSKeyCLI(NSSCLI nssCLI) {
        super("key", "NSS key management commands", nssCLI);

        addModule(new NSSKeyCreateCLI(this));
        addModule(new NSSKeyExportCLI(this));
        addModule(new NSSKeyFindCLI(this));
        addModule(new NSSKeyShowCLI(this));
        addModule(new NSSKeyImportCLI(this));
    }

    public static void printKeyInfo(KeyInfo keyInfo) throws Exception {
        try (PrintWriter out = new PrintWriter(System.out)) {
            printKeyInfo(keyInfo, out);
        }
    }

    public static void printKeyInfo(KeyInfo keyInfo, PrintWriter out) throws Exception {

        KeyId keyID = keyInfo.getKeyId();
        if (keyID != null) {
            out.println("  Key ID: " + keyID.toHexString());
        }

        String nickname = keyInfo.getNickname();
        if (nickname != null) {
            out.println("  Nickname: " + nickname);
        }

        out.println("  Type: " + keyInfo.getType());
        out.println("  Algorithm: " + keyInfo.getAlgorithm());
    }
}
