/*
 * Copyright (c) 2015, WSO2 LLC. (http://www.wso2.com).
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
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.utils.DiagnosticLog;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.application.authenticator.google.GoogleOAuth2AuthenticationConstant.LogConstants.OUTBOUND_AUTH_GOOGLE_SERVICE;

/**
 * This class holds the Google authenticator.
 */
public class GoogleOAuth2Authenticator extends OpenIDConnectAuthenticator {

    private static final long serialVersionUID = -4154255583070524018L;
    private static final Log LOG = LogFactory.getLog(GoogleOAuth2Authenticator.class);
    private static final String ONE_TAP_ENABLED = "one_tap_enabled";
    private static final String CREDENTIAL = "credential";
    private static final String G_CSRF_TOKEN = "g_csrf_token";
    private static final String INTERNAL_SUBMISSION = "internal_submission";
    public static final String STATE = "state";
    private static final String G_CSRF_VALIDATED = "g_csrf_validated";
    private String tokenEndpoint;
    private String oAuthEndpoint;
    private String userInfoURL;

    /**
     * Initiate tokenEndpoint.
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

        // Google one tap flow does not require any special parameter validation at this level.
        if (isOneTapEnabled(request)) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        getComponentId(), FrameworkConstants.LogConstants.ActionIDs.HANDLE_AUTH_STEP);
                diagnosticLogBuilder.resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM)
                        .resultMessage("Handling the Google one tap authentication flow.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            return true;
        }
        return super.canHandle(request);
    }

    @Override
    protected String mapIdToken(AuthenticationContext context, HttpServletRequest request,
                                OAuthClientResponse oAuthResponse) throws AuthenticationFailedException {

        if (isOneTapEnabled(request)) {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientID = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);

            boolean internalSubmission = Boolean.parseBoolean(request.getParameter(INTERNAL_SUBMISSION));

            // This log level will be modified to debug once Google One Tap is successfully onboarded.
            LOG.info("Validating the JWT submitted " + (internalSubmission ? "internally" : "externally"));

            if (!internalSubmission) {
                validateCSRF(request, clientID);
            }

            boolean validJWT = Utils.validateGoogleJWT(request.getParameter(CREDENTIAL), clientID,
                    request.getParameter(STATE), internalSubmission);
            if (!validJWT) {
                throw new AuthenticationFailedException(GoogleErrorConstants.ErrorMessages
                        .TOKEN_VALIDATION_FAILED_ERROR.getCode(), String.format(GoogleErrorConstants.ErrorMessages
                        .TOKEN_VALIDATION_FAILED_ERROR.getMessage(), clientID));
            }
            String idToken = request.getParameter(CREDENTIAL);
            context.setProperty(OIDCAuthenticatorConstants.ID_TOKEN, idToken);
            return idToken;
        }
        return super.mapIdToken(context, request, oAuthResponse);
    }

    /**
     * Validate CSRF based on configuration value for Google One Tap.
     * Google One Tap UI appears on accounts.asg.io domain so the CSRF cookie comes under accounts.asg.io
     * Authenticated response comes to api.asg.io domain with CSRF parameter hence CSRF cookie is blocked.
     * Still there is no configuration from Google side to overcome this issue.
     * Raising this issue under <a href="https://github.com/wso2/product-is/issues/14779">...</a>
     * Once this issue is fixed, this configuration check should be removed.
     *
     * @param request  Authenticated request for commonauth coming from Google.
     * @param clientID Google client ID.
     * @throws AuthenticationFailedException Error when CSRF validation failed.
     */
    private void validateCSRF(HttpServletRequest request, String clientID) throws AuthenticationFailedException {

        boolean validCookies = false;
        boolean validateCSRF = true;

        /*
            This will skip the CSRF validation if it is done already in another layer (e.g. API level).
            That layer should handle the exception flow itself.
         */
        String validatedCSRF = request.getParameter(G_CSRF_VALIDATED);
        if (StringUtils.isNotBlank(validatedCSRF)) {
            String crossRefParamHalf = request.getParameter(G_CSRF_TOKEN);
            if (StringUtils.isNotBlank(crossRefParamHalf) && validatedCSRF.equals(crossRefParamHalf)) {
                validCookies = true;
            }
        } else {
            String enableCSRFValidationForGOT = getAuthenticatorConfig().getParameterMap()
                    .get(GoogleOAuth2AuthenticationConstant.ENABLE_CSRF_VALIDATION_FOR_GOT);

            if (StringUtils.isNotBlank(enableCSRFValidationForGOT)) {
                validateCSRF = Boolean.parseBoolean(enableCSRFValidationForGOT);
            }
            if (validateCSRF) {
                validCookies = validateCSRFCookies(request);
            }
        }
        if (validateCSRF && !validCookies) {
            throw new AuthenticationFailedException(GoogleErrorConstants.ErrorMessages
                    .CSRF_VALIDATION_FAILED_ERROR.getCode(), String.format(GoogleErrorConstants.ErrorMessages
                    .CSRF_VALIDATION_FAILED_ERROR.getMessage(), clientID));
        }
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
            if (LOG.isDebugEnabled()) {
                LOG.debug("Passing mapAccessToken:Google One Tap authentication flow");
            }
            return;
        }
        super.mapAccessToken(request, context, oAuthResponse);
    }

    @Override
    protected OAuthClientResponse requestAccessToken(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        // Google One Tap flow does not require this step.
        if (isOneTapEnabled(request)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Passing generateOauthResponse:Google One Tap authentication flow");
            }
            return null;
        }
        return super.requestAccessToken(request, context);
    }

    /**
     * Initiate authorization server endpoint.
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

        if (userInfoURL == null) {
            initUserInfoURL();
        }

        return userInfoURL;
    }

    /**
     * Get Authorization Server Endpoint.
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
     * Get Token Endpoint.
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
     * Get Scope.
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
    protected String getAuthenticateUser(AuthenticationContext context, Map<String, Object> jsonObject,
                                         OAuthClientResponse token) {
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
     * Get Configuration Properties.
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
        clientId.setDisplayOrder(++parameterCount);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("The client secret value of the Google identity provider.");
        clientSecret.setDisplayOrder(++parameterCount);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName("Callback URL");
        callbackUrl.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        callbackUrl.setDescription("The callback URL used to obtain Google credentials.");
        callbackUrl.setDisplayOrder(++parameterCount);
        configProperties.add(callbackUrl);

        Property scope = new Property();
        scope.setDisplayName("Additional Query Parameters");
        scope.setName("AdditionalQueryParameters");
        scope.setValue("scope=openid email profile");
        scope.setDescription("Additional query parameters to be sent to Google.");
        scope.setDisplayOrder(++parameterCount);
        configProperties.add(scope);

        Property googleOneTap = new Property();
        googleOneTap.setName(GoogleOAuth2AuthenticationConstant.GOOGLE_ONE_TAP_ENABLED);
        googleOneTap.setDisplayName(GoogleOAuth2AuthenticationConstant.GOOGLE_ONE_TAP_DISPLAY_NAME);
        googleOneTap.setRequired(false);
        googleOneTap.setType("boolean");
        googleOneTap.setDescription(GoogleOAuth2AuthenticationConstant.GOOGLE_ONE_TAP_DESCRIPTION);
        googleOneTap.setDisplayOrder(++parameterCount);
        configProperties.add(googleOneTap);

        return configProperties;
    }

    /**
     * Get Friendly Name.
     *
     * @return
     */
    @Override
    public String getFriendlyName() {
        return GoogleOAuth2AuthenticationConstant.GOOGLE_CONNECTOR_FRIENDLY_NAME;
    }

    /**
     * Get Name.
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
               if (LOG.isDebugEnabled()) {
                   LOG.debug("Found no Parameter map for connector " + getName());
               }
           }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("FileBasedConfigBuilder returned null AuthenticatorConfigs for the connector " +
                        getName());
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Authenticator " + getName() + " is using the claim dialect uri " + claimDialectUri);
        }
        return claimDialectUri;
    }

    @Override
    protected void buildClaimMappings(Map<ClaimMapping, String> claims, Map.Entry<String, Object> entry,
                                      String separator) {
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
        if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
            LOG.debug("Adding claim mapping : " + claimUri + " <> " + claimUri + " : " + claimValue);
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
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Empty JSON response from user info endpoint. Unable to fetch user claims." +
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

                if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)
                        && jsonObject.get(key) != null) {
                    LOG.debug("Adding claims from end-point data mapping : " + key + " - " + jsonObject.get(key)
                            .toString());
                }
            }
        } catch (IOException e) {
            LOG.error("Communication error occurred while accessing user info endpoint", e);
        }
        return claims;
    }

    @Override
    public String getI18nKey() {

        return GoogleOAuth2AuthenticationConstant.AUTHENTICATOR_GOOGLE;
    }

    @Override
    protected String getComponentId() {

        return OUTBOUND_AUTH_GOOGLE_SERVICE;
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
            if (LOG.isDebugEnabled()) {
                LOG.debug("No valid cookie found for Google One Tap authentication.");
            }
            return false;
        }
        Cookie crossRefCookie = Arrays.stream(request.getCookies())
                .filter(cookie -> G_CSRF_TOKEN.equalsIgnoreCase(cookie.getName()))
                .findFirst().orElse(null);

        if (crossRefCookie == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No CSRF cookie found. Invalid request.");
            }
            return false;
        }
        String crossRefCookieHalf = crossRefCookie.getValue();
        String crossRefParamHalf = request.getParameter(G_CSRF_TOKEN);

        if (StringUtils.isEmpty(crossRefParamHalf) || StringUtils.isEmpty(crossRefCookieHalf)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No CSRF parameter found. Invalid request.");
            }
            return false;
        }
        if (!crossRefParamHalf.equals(crossRefCookieHalf)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("CSRF validation failed for Google One Tap.");
            }
            return false;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Validated CSRF cookies successfully for Google One Tap.");
        }
        return true;
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
