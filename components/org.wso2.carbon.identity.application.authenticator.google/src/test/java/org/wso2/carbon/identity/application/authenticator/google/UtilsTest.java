/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.google;

import junit.framework.TestCase;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

import java.io.File;
import java.util.Scanner;

public class UtilsTest extends TestCase {

    // Token is fed by a text file
    String token;
    String audience = "132708446238-d3lpgkp0t8fiko20ii217lmbdftnojei.apps.googleusercontent.com";

    public void setUp() throws Exception {

        super.setUp();
        File file = new File(
                "/Users/indeewariwijesiri/Documents/Servers/1.0.4/identity-outbound-auth-google/components/org.wso2.carbon.identity.application.authenticator.google/src/test/resources/input.txt");
        Scanner sc = new Scanner(file);

        if (sc.hasNextLine()) {
            token = sc.nextLine();
        }

    }

    public void tearDown() throws Exception {

        super.tearDown();
    }

    public void testValidateJWT() {

        try {
            assertTrue(Utils.validateJWT(token, audience));
        } catch (AuthenticationFailedException e) {
            fail("Exception! : " + e.getErrorCode() + " : " + e.getMessage());
        }
    }
}