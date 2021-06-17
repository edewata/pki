//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.user;

import org.junit.Assert;
import org.junit.Test;

public class UserDataTest {

    UserData userData;

    public UserDataTest() {
        userData = new UserData();
        userData.setID("testuser");
        userData.setFullName("Test User");
        userData.setEmail("testuser@example.com");
        userData.setPassword("12345");
        userData.setPhone("1234567890");
        userData.setState("1");
    }

    @Test
    public void testXML() throws Exception {

        String xml = userData.toXML();
        System.out.println("Before: " + xml);

        UserData after = UserData.fromXML(xml);
        System.out.println("After: " + after.toXML());

        Assert.assertEquals(userData, after);
    }

    @Test
    public void testJSON() throws Exception {

        String json = userData.toJSON();
        System.out.println("Before: " + json);

        UserData after = UserData.fromJSON(json);
        System.out.println("After: " + after.toJSON());

        Assert.assertEquals(userData, after);
    }
}
