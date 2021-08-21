package com.netscape.certsrv.cert;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class CertSearchRequestTest {

    private static CertSearchRequest before = new CertSearchRequest();

    @BeforeClass
    public static void setUpBefore() {
        before.setValidNotBeforeFrom("1111");
        before.setValidNotBeforeTo("2222");
        before.setValidNotAfterFrom("3333");
        before.setValidNotAfterTo("4444");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        CertSearchRequest afterXML = CertSearchRequest.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertSearchRequest afterJSON = JSONSerializer.fromJSON(json, CertSearchRequest.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }


}
