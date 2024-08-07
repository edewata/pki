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
package com.netscape.certsrv.dbs.certdb;

import java.io.Serializable;
import java.math.BigInteger;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * The CertId class represents the identifier for a particular
 * cert record. This identifier may be used to retrieve the cert record
 * from the database.
 * <p>
 *
 * @author Endi S. Dewata
 * @version $Revision$ $Date$
 */
// TODO: Make a common base class for cert id's and key ids
public class CertId implements Serializable, JSONSerializer {

    @JsonProperty
    protected BigInteger value;

    /**
     * Creates a new CertId from its string representation.
     * <p>
     *
     * @param id
     *            a string containing the decimal or hex value for the identifier.
     */
    public CertId(String id) {
        if (id != null) {
            id = id.trim();
            if (id.startsWith("0x")) { // hex
                value = new BigInteger(id.substring(2), 16);
            } else { // decimal
                value = new BigInteger(id);
            }
        }
    }

    /**
     * Creates a new CertId from its BigInteger representation.
     * <p>
     *
     * @param id
     *            a BigInteger containing the identifier.
     */
    public CertId(BigInteger id) {
        value = id;
    }

    /**
     * Creates a new CertId from its integer representation.
     * <p>
     *
     * @param id
     *            an integer containing the identifier.
     */
    public CertId(int id) {
        value = BigInteger.valueOf(id);
    }

    /**
     * Converts the CertId into its BigInteger representation.
     * <p>
     *
     * @return
     *         a BigInteger containing the identifier.
     */
    public BigInteger toBigInteger() {
        return value;
    }

    /**
     * Converts the CertId into its string representation. The string
     * form can be stored in a database (such as the LDAP directory)
     * <p>
     *
     * @return
     *         a string containing the decimal (base 10) value for the identifier.
     */
    @Override
    public String toString() {
        return value.toString();
    }

    /**
     * Converts the CertId into its hex string representation. The string
     * form can be stored in a database (such as the LDAP directory)
     *
     * @return
     *         a string containing the hex (hex 16) value for the identifier.
     */
    @JsonValue
    public String toHexString() {
        return "0x" + value.toString(16);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((value == null) ? 0 : value.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CertId other = (CertId) obj;
        if (value == null) {
            if (other.value != null)
                return false;
        } else if (!value.equals(other.value))
            return false;
        return true;
    }
}
