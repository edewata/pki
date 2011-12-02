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
package com.netscape.certsrv.publish;


import com.netscape.certsrv.ldap.ELdapException;


/**
 * Exception for Publisher not found. Required for successful publishing.
 *
 * @version $Revision$ $Date$
 */
public class EPublisherNotFound extends ELdapException {

    /**
     *
     */
    private static final long serialVersionUID = 6159885167931517580L;

    /**
     * Constructs a exception for a missing required publisher.
     * @param errorString Detailed error message.
     */
    public EPublisherNotFound(String errorString) {
        super(errorString);
    }
}
