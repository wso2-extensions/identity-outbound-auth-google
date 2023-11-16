/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.google;

import java.util.Map;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCSocialSignupExecutor;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;

/**
 * Google Registration Executor.
 */
public class GoogleSignupExecutor extends OIDCSocialSignupExecutor {

    private static final GoogleSignupExecutor instance = new GoogleSignupExecutor();
    private static final String GOOGLE_SIGNUP_EXECUTOR = "GoogleSignupExecutor";

    public static GoogleSignupExecutor getInstance() {

        return instance;
    }

    @Override
    public String getName() {

        return GOOGLE_SIGNUP_EXECUTOR;
    }

    @Override
    public String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        String authzEndpoint = authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);
        if (authzEndpoint == null) {
            authzEndpoint = IdentityApplicationConstants.GOOGLE_OAUTH_URL;
        }
        return authzEndpoint;
    }

    @Override
    public String getTokenEndpoint(Map<String, String> authenticatorProperties) {

        String tokenEndpoint = authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
        if (tokenEndpoint == null) {
            tokenEndpoint = IdentityApplicationConstants.GOOGLE_TOKEN_URL;
        }
        return tokenEndpoint;
    }

    @Override
    public String getUserInfoEndpoint(Map<String, String> authenticatorProperties) {

        String userInfoEndpoint =
                authenticatorProperties.get(IdentityApplicationConstants.Authenticator.OIDC.USER_INFO_URL);
        if (userInfoEndpoint == null) {
            userInfoEndpoint = IdentityApplicationConstants.GOOGLE_USERINFO_URL;
        }
        return userInfoEndpoint;
    }

    @Override
    public String getScope(Map<String, String> authenticatorProperties) {

        return GoogleOAuth2AuthenticationConstant.GOOGLE_SCOPE;
    }

    @Override
    public String getAuthenticateUser(Map<String, Object> jsonObject) {

        if (jsonObject.get(OIDCAuthenticatorConstants.Claim.EMAIL) == null) {
            return (String) jsonObject.get("sub");
        } else {
            return (String) jsonObject.get(OIDCAuthenticatorConstants.Claim.EMAIL);
        }
    }
}
