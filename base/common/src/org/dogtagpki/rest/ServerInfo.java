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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.rest;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.ResourceMessage;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="ServerInfo")
public class ServerInfo extends ResourceMessage {

    private static Logger logger = LoggerFactory.getLogger(ServerInfo.class);

    public static Marshaller marshaller;
    public static Unmarshaller unmarshaller;

    static {
        try {
            marshaller = JAXBContext.newInstance(ServerInfo.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            unmarshaller = JAXBContext.newInstance(ServerInfo.class).createUnmarshaller();
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    String name;
    String version;
    String warning;

    @XmlElement(name="Name")
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @XmlElement(name="Version")
    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    @XmlElement(name="Warning")
    public String getWarning() {
        return warning;
    }

    public void setWarning(String warning) {
        this.warning = warning;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((warning == null) ? 0 : warning.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((version == null) ? 0 : version.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        ServerInfo other = (ServerInfo) obj;
        if (warning == null) {
            if (other.warning != null)
                return false;
        } else if (!warning.equals(other.warning))
            return false;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        if (version == null) {
            if (other.version != null)
                return false;
        } else if (!version.equals(other.version))
            return false;
        return true;
    }

    public String toString() {
        try {
            StringWriter sw = new StringWriter();
            marshaller.marshal(this, sw);
            return sw.toString();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static ServerInfo valueOf(String string) throws Exception {
        return (ServerInfo)unmarshaller.unmarshal(new StringReader(string));
    }

    public static void main(String args[]) throws Exception {

        ServerInfo before = new ServerInfo();
        before.setName("PKI Server");
        before.setVersion("10.4");
        before.setWarning(
                "WARNING!\n" +
                "Access to this service is restricted to those individuals with " +
                "specific permissions.");

        String string = before.toString();
        System.out.println(string);

        ServerInfo after = ServerInfo.valueOf(string);
        System.out.println(before.equals(after));
    }
}
