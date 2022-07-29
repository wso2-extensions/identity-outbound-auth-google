/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.google;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.apache.v2.ApacheHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONValue;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public class GoogleOAuth2Authenticator extends OpenIDConnectAuthenticator {

    private static final long serialVersionUID = -4154255583070524018L;
    private static final Log log = LogFactory.getLog(GoogleOAuth2Authenticator.class);
    private static final String ONE_TAP_ENABLED = "one_tap_enabled";
    private static final String CREDENTIAL = "credential";
    private static final String G_CSRF_TOKEN = "g_csrf_token";
    private String tokenEndpoint;
    private String oAuthEndpoint;
    private String userInfoURL;

    /**
     * Initiate tokenEndpoint
     */
    private void initTokenEndpoint() {

        this.tokenEndpoint = getAuthenticatorConfig().getParameterMap().get(GoogleOAuth2AuthenticationConstant
                .GOOGLE_TOKEN_ENDPOINT);
        if (StringUtils.isBlank(this.tokenEndpoint)) {
            this.tokenEndpoint = IdentityApplicationConstants.GOOGLE_TOKEN_URL;
        }
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        // Google one tap flow does not require any special parameter validation at this level
        if (isOneTapEnabled(request)) {
            return true;
        }
        return super.canHandle(request);
    }

    /**
     * This function validates the JWT token by its content using Google libraries.
     *
     * @param request  HttpServletRequest. Authentication request with JWT token.
     * @param clientID String. Authenticator client ID to check validity
     * @return Validity of the returned JWT token returned via Google One Tap.
     */
    private boolean validateJWTFromGOT(HttpServletRequest request, String clientID) {

        String idTokenString = request.getParameter(CREDENTIAL);
        // Verifying the ID token.
        ApacheHttpTransport transport = new ApacheHttpTransport();
        GsonFactory jsonFactory = new GsonFactory();
        /*
          Specify the CLIENT_ID of the app that accesses the backend:
          Or, if multiple clients access the backend:
          .setAudience(Arrays.asList(CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3)).
         */
        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
                .setAudience(Collections.singletonList(clientID))
                .build();
        GoogleIdToken idToken = null;
        try {
            idToken = verifier.verify(idTokenString);
        } catch (GeneralSecurityException e) {
            log.error("In-secured JWT returned from Google One Tap.", e);
        } catch (IOException e) {
            log.error("Exception while validating the JWT returned from Google One Tap.", e);
        }
        if (idToken != null) {
            if (log.isDebugEnabled()) {
                log.debug("JWT token validated successfully for Google One Tap.");
            }
            return true;
        }
        return false;
    }

    /**
     * This function validates the CSRF double-sided cookie returned from Google One Tap respond.
     * The request is considered as non-attacked request if the CSRF cookie and the parameter is equal.
     *
     * @param request HttpServletRequest. Authentication request with Google One Tap auth payloads.
     * @return Integrity of the authentication request sent via Google One Tap.
     */
    private boolean validateCSRFCookies(HttpServletRequest request) {

        if (request.getCookies() == null) {
            if (log.isDebugEnabled()) {
                log.debug("No valid cookie found for Google One Tap authentication.");
            }
            return false;
        }
        List<Cookie> crossRefCookies = Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equalsIgnoreCase(G_CSRF_TOKEN))
                .collect(Collectors.toList());

        if (crossRefCookies.isEmpty() || crossRefCookies.get(0) == null) {
            if (log.isDebugEnabled()) {
                log.debug("No CSRF cookie found. Invalid request.");
            }
            return false;
        }
        String crossRefCookieHalf = crossRefCookies.get(0).getValue();
        String crossRefParamHalf = request.getParameter(G_CSRF_TOKEN);

        if (StringUtils.isEmpty(crossRefParamHalf) || StringUtils.isEmpty(crossRefCookieHalf)) {
            if (log.isDebugEnabled()) {
                log.debug("No CSRF parameter found. Invalid request.");
            }
            return false;
        }
        if (!crossRefParamHalf.equals(crossRefCookieHalf)) {
            if (log.isDebugEnabled()) {
                log.debug("CSRF validation failed for Google One Tap.");
            }
            return false;
        }
        if (log.isDebugEnabled()) {
            log.debug("Validated CSRF cookies successfully for Google One Tap.");
        }
        return true;
    }

    @Override
    protected String mapIdToken(AuthenticationContext context, HttpServletRequest request,
                                OAuthClientResponse oAuthResponse) throws AuthenticationFailedException{

        /*
          Validity of the
          1. CSRF cookies
          2. JWT token
          decide the ability of handling the authentication request in Google One Tap flow.
         */
        if (isOneTapEnabled(request)) {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientID = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);

            boolean validCookies = validateCSRFCookies(request);
            if (!validCookies) {
                throw new AuthenticationFailedException(GoogleErrorConstants.ErrorMessages
                        .CSRF_VALIDATION_FAILED_ERROR.getCode(), String.format(GoogleErrorConstants.ErrorMessages
                        .CSRF_VALIDATION_FAILED_ERROR.getMessage(), getName(), clientID));
            }

            boolean validJWT = validateJWTFromGOT(request, clientID);
            if (!validJWT) {
                throw new AuthenticationFailedException(GoogleErrorConstants.ErrorMessages
                        .TOKEN_VALIDATION_FAILED_ERROR.getCode(), String.format(GoogleErrorConstants.ErrorMessages
                        .TOKEN_VALIDATION_FAILED_ERROR.getMessage(), getName(), clientID));
            }
            String idToken = request.getParameter(CREDENTIAL);
            context.setProperty(OIDCAuthenticatorConstants.ID_TOKEN, idToken);
            return idToken;
        }
        return super.mapIdToken(context, request, oAuthResponse);
    }

    @Override
    protected boolean isInitialRequest(AuthenticationContext context, HttpServletRequest request) {

        // Google One Tap flow returns the JWT token at the very first callback.
        if (isOneTapEnabled(request)) {
            context.setCurrentAuthenticator(getName());
            return false;
        }
        return super.isInitialRequest(context, request);
    }

    @Override
    protected void mapAccessToken(HttpServletRequest request, AuthenticationContext context,
                                  OAuthClientResponse oAuthResponse) throws AuthenticationFailedException {

        // Google One Tap flow does not require this step.
        if (isOneTapEnabled(request)) {
            if (log.isDebugEnabled()) {
                log.debug("Passing mapAccessToken:Google One Tap authentication flow");
            }
            return;
        }
        super.mapAccessToken(request, context, oAuthResponse);
    }

    @Override
    protected OAuthClientResponse generateOauthResponse(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        // Google One Tap flow does not require this step.
        if (isOneTapEnabled(request)) {
            if (log.isDebugEnabled()) {
                log.debug("Passing generateOauthResponse:Google One Tap authentication flow");
            }
            return null;
        }
        return super.generateOauthResponse(request, context);
    }

    /**
     * Initiate authorization server endpoint
     */
    private void initOAuthEndpoint() {
        this.oAuthEndpoint = getAuthenticatorConfig().getParameterMap().get(GoogleOAuth2AuthenticationConstant
                .GOOGLE_AUTHZ_ENDPOINT);
        if (StringUtils.isBlank(this.oAuthEndpoint)) {
            this.oAuthEndpoint = IdentityApplicationConstants.GOOGLE_OAUTH_URL;
        }
    }

    /**
     * Initialize the Yahoo user info url.
     */
    private void initUserInfoURL() {

        userInfoURL = getAuthenticatorConfig()
                .getParameterMap()
                .get(GoogleOAuth2AuthenticationConstant.GOOGLE_USERINFO_ENDPOINT);

        if (userInfoURL == null) {
            userInfoURL = IdentityApplicationConstants.GOOGLE_USERINFO_URL;
        }
    }

    /**
     * Get the user info endpoint url.
     * @return User info endpoint url.
     */
    private String getUserInfoURL() {

        if(userInfoURL == null) {
            initUserInfoURL();
        }

        return userInfoURL;
    }

    /**
     * Get Authorization Server Endpoint
     *
     * @param authenticatorProperties this is not used currently in the method
     * @return oAuthEndpoint
     */
    @Override
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {
        if (StringUtils.isBlank(this.oAuthEndpoint)) {
            initOAuthEndpoint();
        }
        return this.oAuthEndpoint;
    }

    /**
     * Get Token Endpoint
     *
     * @param authenticatorProperties this is not used currently in the method
     * @return tokenEndpoint
     */
    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {
        if (StringUtils.isBlank(this.tokenEndpoint)) {
            initTokenEndpoint();
        }
        return this.tokenEndpoint;
    }

    /**
     * Get Scope
     *
     * @param scope
     * @param authenticatorProperties
     * @return
     */
    @Override
    protected String getScope(String scope,
                              Map<String, String> authenticatorProperties) {
        return GoogleOAuth2AuthenticationConstant.GOOGLE_SCOPE;
    }


    @Override
    protected String getAuthenticateUser(AuthenticationContext context, Map<String, Object> jsonObject, OAuthClientResponse token) {
        if (jsonObject.get(OIDCAuthenticatorConstants.Claim.EMAIL) == null) {
            return (String) jsonObject.get("sub");
        } else {
            return (String) jsonObject.get(OIDCAuthenticatorConstants.Claim.EMAIL);
        }
    }

    /**
     * Get google user info endpoint.
     * @param token OAuth client response.
     * @return User info endpoint.
     */
    @Override
    protected String getUserInfoEndpoint(OAuthClientResponse token, Map<String, String> authenticatorProperties) {
        return getUserInfoURL();
    }

    @Override
    protected String getQueryString(Map<String, String> authenticatorProperties) {
        return authenticatorProperties.get(GoogleOAuth2AuthenticationConstant.ADDITIONAL_QUERY_PARAMS);
    }

    /**
     * Get Configuration Properties
     *
     * @return
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();
        int parameterCount = 0;

        Property clientId = new Property();
        clientId.setName(OIDCAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client ID");
        clientId.setRequired(true);
        clientId.setDescription("The client identifier value of the Google identity provider.");
        clientId.setDisplayOrder(parameterCount++);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("The client secret value of the Google identity provider.");
        clientSecret.setDisplayOrder(parameterCount++);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName("Callback URL");
        callbackUrl.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        callbackUrl.setDescription("The callback URL used to obtain Google credentials.");
        callbackUrl.setDisplayOrder(parameterCount++);
        configProperties.add(callbackUrl);

        Property scope = new Property();
        scope.setDisplayName("Additional Query Parameters");
        scope.setName("AdditionalQueryParameters");
        scope.setValue("scope=openid email profile");
        scope.setDescription("Additional query parameters to be sent to Google.");
        scope.setDisplayOrder(parameterCount++);
        configProperties.add(scope);

        Property googleOneTap = new Property();
        googleOneTap.setName(GoogleOAuth2AuthenticationConstant.GOOGLE_ONE_TAP_ENABLED);
        googleOneTap.setDisplayName(GoogleOAuth2AuthenticationConstant.GOOGLE_ONE_TAP_DISPLAY_NAME);
        googleOneTap.setRequired(false);
        googleOneTap.setType("boolean");
        googleOneTap.setDescription(GoogleOAuth2AuthenticationConstant.GOOGLE_ONE_TAP_DESCRIPTION);
        googleOneTap.setDisplayOrder(parameterCount++);
        configProperties.add(googleOneTap);

        return configProperties;
    }

    /**
     * Get Friendly Name
     *
     * @return
     */
    @Override
    public String getFriendlyName() {
        return GoogleOAuth2AuthenticationConstant.GOOGLE_CONNECTOR_FRIENDLY_NAME;
    }

    /**
     * GetName
     *
     * @return
     */
    @Override
    public String getName() {
        return GoogleOAuth2AuthenticationConstant.GOOGLE_CONNECTOR_NAME;
    }

    @Override
    public String getClaimDialectURI() {
        String claimDialectUri = super.getClaimDialectURI();
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(getName());
        if (authConfig != null) {
           Map<String, String> parameters = authConfig.getParameterMap();
           if (parameters != null && parameters.containsKey(GoogleOAuth2AuthenticationConstant.
                  CLAIM_DIALECT_URI_PARAMETER)) {
               claimDialectUri = parameters.get(GoogleOAuth2AuthenticationConstant.CLAIM_DIALECT_URI_PARAMETER);
           } else {
               if (log.isDebugEnabled()) {
                   log.debug("Found no Parameter map for connector " + getName());
               }
           }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("FileBasedConfigBuilder returned null AuthenticatorConfigs for the connector " +
                        getName());
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Authenticator " + getName() + " is using the claim dialect uri " + claimDialectUri);
        }
        return claimDialectUri;
    }

    @Override
    protected void buildClaimMappings(Map<ClaimMapping, String> claims, Map.Entry<String, Object> entry, String separator) {
        String claimValue = null;
        String claimUri   = "";
        if (StringUtils.isBlank(separator)) {
            separator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
        }
        try {
            JSONArray jsonArray = (JSONArray) JSONValue.parseWithException(entry.getValue().toString());
            if (jsonArray != null && jsonArray.size() > 0) {
                Iterator attributeIterator = jsonArray.iterator();
                while (attributeIterator.hasNext()) {
                    if (claimValue == null) {
                        claimValue = attributeIterator.next().toString();
                    } else {
                        claimValue = claimValue + separator + attributeIterator.next().toString();
                    }
                }

            }
        } catch (Exception e) {
            claimValue = entry.getValue().toString();
        }
        String claimDialectUri = getClaimDialectURI();
        if (super.getClaimDialectURI() != null && !super.getClaimDialectURI().equals(claimDialectUri)) {
            claimUri = claimDialectUri + "/";
        }

        claimUri += entry.getKey();
        claims.put(ClaimMapping.build(claimUri, claimUri, null, false), claimValue);
        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
            log.debug("Adding claim mapping : " + claimUri + " <> " + claimUri + " : " + claimValue);
        }
    }

    /**
     * Get subject attributes.
     * @param token OAuthClientResponse
     * @param authenticatorProperties Map<String, String> (Authenticator property, Property value)
     * @return Map<ClaimMapping, String> Claim mappings.
     */
    protected Map<ClaimMapping, String> getSubjectAttributes(OAuthClientResponse token,
                                                             Map<String, String> authenticatorProperties) {

        Map<ClaimMapping, String> claims = new HashMap<>();

        // There is no need of retrieving an auth token for Google One Tap since it already has the JWT token.
        if (token == null) {
            return claims;
        }
        try {
            String accessToken = token.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);
            String url = getUserInfoEndpoint(token, authenticatorProperties);
            String json = sendRequest(url, accessToken);

            if (StringUtils.isBlank(json)) {
                if (log.isDebugEnabled()) {
                    log.debug("Empty JSON response from user info endpoint. Unable to fetch user claims." +
                            " Proceeding without user claims");
                }
                return claims;
            }

            Map<String, Object> jsonObject = JSONUtils.parseJSON(json);

            for (Map.Entry<String, Object> data : jsonObject.entrySet()) {
                String key = data.getKey();
                Object value = data.getValue();
                String claimDialectUri = getClaimDialectURI();
                if (super.getClaimDialectURI() != null && !super.getClaimDialectURI().equals(claimDialectUri)) {
                    key = claimDialectUri + "/" + key;
                }
                if (value != null) {
                    claims.put(ClaimMapping.build(key, key, null, false), value.toString());
                }

                if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)
                        && jsonObject.get(key) != null) {
                    log.debug("Adding claims from end-point data mapping : " + key + " - " + jsonObject.get(key)
                            .toString());
                }
            }
        } catch (IOException e) {
            log.error("Communication error occurred while accessing user info endpoint", e);
        }
        return claims;
    }

    /**
     * A utility function to check whether user has requested a Google One Tap authentication.
     *
     * @param request The authentication request.
     * @return Whether Google One Tap authentication is requested or not.
     */
    private boolean isOneTapEnabled(HttpServletRequest request) {

        return Boolean.parseBoolean(request.getParameter(ONE_TAP_ENABLED));
    }
}
