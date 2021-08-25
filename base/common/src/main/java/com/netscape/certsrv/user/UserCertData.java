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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.user;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.StringTokenizer;

import javax.ws.rs.FormParam;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.base.Link;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class UserCertData implements JSONSerializer {

    Integer version;
    CertId serialNumber;
    String issuerDN;
    String subjectDN;
    String prettyPrint;
    String encoded;

    Link link;

    public String getID() {
        if (version == null && serialNumber == null && issuerDN == null && subjectDN == null) {
            return null;
        } else {
            return version + ";" + serialNumber + ";" + issuerDN + ";" + subjectDN;
        }
    }

    public void setID(String id) {
        StringTokenizer st = new StringTokenizer(id, ";");
        version = Integer.valueOf(st.nextToken());
        serialNumber = new CertId(st.nextToken());
        issuerDN = st.nextToken();
        subjectDN = st.nextToken();
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    public CertId getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(CertId serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public String getPrettyPrint() {
        return prettyPrint;
    }

    public void setPrettyPrint(String prettyPrint) {
        this.prettyPrint = prettyPrint;
    }

    @FormParam(Constants.PR_USER_CERT)
    public String getEncoded() {
        return encoded;
    }

    public void setEncoded(String encoded) {
        this.encoded = encoded;
    }

    public Link getLink() {
        return link;
    }

    public void setLink(Link link) {
        this.link = link;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((encoded == null) ? 0 : encoded.hashCode());
        result = prime * result + ((issuerDN == null) ? 0 : issuerDN.hashCode());
        result = prime * result + ((prettyPrint == null) ? 0 : prettyPrint.hashCode());
        result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());
        result = prime * result + ((version == null) ? 0 : version.hashCode());
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
        UserCertData other = (UserCertData) obj;
        if (encoded == null) {
            if (other.encoded != null)
                return false;
        } else if (!encoded.equals(other.encoded))
            return false;
        if (issuerDN == null) {
            if (other.issuerDN != null)
                return false;
        } else if (!issuerDN.equals(other.issuerDN))
            return false;
        if (prettyPrint == null) {
            if (other.prettyPrint != null)
                return false;
        } else if (!prettyPrint.equals(other.prettyPrint))
            return false;
        if (serialNumber == null) {
            if (other.serialNumber != null)
                return false;
        } else if (!serialNumber.equals(other.serialNumber))
            return false;
        if (subjectDN == null) {
            if (other.subjectDN != null)
                return false;
        } else if (!subjectDN.equals(other.subjectDN))
            return false;
        if (version == null) {
            if (other.version != null)
                return false;
        } else if (!version.equals(other.version))
            return false;
        return true;
    }

    public Element toDOM(Document document) {

        Element element = document.createElement("UserCertData");

        element.setAttribute("id", getID());

        if (version != null) {
            Element versionElement = document.createElement("Version");
            versionElement.appendChild(document.createTextNode(Integer.toString(version)));
            element.appendChild(versionElement);
        }

        if (serialNumber != null) {
            Element serialNumberElement = document.createElement("SerialNumber");
            serialNumberElement.appendChild(document.createTextNode(serialNumber.toHexString()));
            element.appendChild(serialNumberElement);
        }

        if (issuerDN != null) {
            Element issuerDNElement = document.createElement("IssuerDN");
            issuerDNElement.appendChild(document.createTextNode(issuerDN));
            element.appendChild(issuerDNElement);
        }

        if (subjectDN != null) {
            Element subjectDNElement = document.createElement("SubjectDN");
            subjectDNElement.appendChild(document.createTextNode(subjectDN));
            element.appendChild(subjectDNElement);
        }

        if (prettyPrint != null) {
            Element prettyPrintElement = document.createElement("PrettyPrint");
            prettyPrintElement.appendChild(document.createTextNode(prettyPrint));
            element.appendChild(prettyPrintElement);
        }

        if (encoded != null) {
            Element encodedElement = document.createElement("Encoded");
            encodedElement.appendChild(document.createTextNode(encoded));
            element.appendChild(encodedElement);
        }

        if (link != null) {
            Element linkElement = link.toDOM(document);
            element.appendChild(linkElement);
        }

        return element;
    }

    public static UserCertData fromDOM(Element element) {

        UserCertData data = new UserCertData();

        NodeList versionList = element.getElementsByTagName("Version");
        if (versionList.getLength() > 0) {
            String value = versionList.item(0).getTextContent();
            data.setVersion(Integer.parseInt(value));
        }

        NodeList serialNumberList = element.getElementsByTagName("SerialNumber");
        if (serialNumberList.getLength() > 0) {
            String value = serialNumberList.item(0).getTextContent();
            data.setSerialNumber(new CertId(value));
        }

        NodeList issuerDNList = element.getElementsByTagName("IssuerDN");
        if (issuerDNList.getLength() > 0) {
            String value = issuerDNList.item(0).getTextContent();
            data.setIssuerDN(value);
        }

        NodeList subjectDNList = element.getElementsByTagName("SubjectDN");
        if (subjectDNList.getLength() > 0) {
            String value = subjectDNList.item(0).getTextContent();
            data.setSubjectDN(value);
        }

        NodeList prettyPrintList = element.getElementsByTagName("PrettyPrint");
        if (prettyPrintList.getLength() > 0) {
            String value = prettyPrintList.item(0).getTextContent();
            data.setPrettyPrint(value);
        }

        NodeList encodedList = element.getElementsByTagName("Encoded");
        if (encodedList.getLength() > 0) {
            String value = encodedList.item(0).getTextContent();
            data.setEncoded(value);
        }

        NodeList linkList = element.getElementsByTagName("Link");
        if (linkList.getLength() > 0) {
            Element linkElement = (Element) linkList.item(0);
            Link link = Link.fromDOM(linkElement);
            data.setLink(link);
        }

        return data;
    }

    public String toXML() throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element element = toDOM(document);
        document.appendChild(element);

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");

        DOMSource domSource = new DOMSource(document);
        StringWriter sw = new StringWriter();
        StreamResult streamResult = new StreamResult(sw);
        transformer.transform(domSource, streamResult);

        return sw.toString();
    }

    public static UserCertData fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element element = document.getDocumentElement();
        return fromDOM(element);
    }

    @Override
    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
