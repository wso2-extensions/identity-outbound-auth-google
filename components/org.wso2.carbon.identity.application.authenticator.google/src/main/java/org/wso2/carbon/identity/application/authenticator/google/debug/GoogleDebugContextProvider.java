/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.google.debug;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.google.GoogleExecutor;
import org.wso2.carbon.identity.application.authenticator.google.GoogleOAuth2AuthenticationConstant;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.OIDCDebugConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OIDCConfigurationExtractor;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.debug.framework.core.DebugContextProvider;
import org.wso2.carbon.identity.debug.framework.exception.ContextResolutionException;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Google-specific debug context provider.
 * Reuses the OIDC debug payload shape while resolving Google-specific authenticator defaults.
 */
public class GoogleDebugContextProvider extends DebugContextProvider {

    private static final Log LOG = LogFactory.getLog(GoogleDebugContextProvider.class);
    private static final String CONNECTION_ID_KEY = "connectionId";
    private static final String RESOURCE_TYPE_KEY = "resourceType";

    @Override
    public DebugContext resolveContext(Map<String, Object> params) throws ContextResolutionException {

        String connectionId = (String) params.get(CONNECTION_ID_KEY);
        String resourceType = (String) params.get(RESOURCE_TYPE_KEY);

        if (StringUtils.isEmpty(connectionId)) {
            throw new ContextResolutionException("IdP ID is null or empty");
        }

        Map<String, Object> context = new HashMap<>();
        try {
            String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
            IdentityProvider idp = retrieveIdentityProvider(connectionId, tenantDomain);
            validateIdpIsEnabled(idp);

            populateIdpContextProperties(context, idp);

            FederatedAuthenticatorConfig authenticatorConfig = findGoogleAuthenticatorConfig(idp, resourceType);
            if (authenticatorConfig == null) {
                throw new ContextResolutionException("No Google authenticator configuration found for IdP: "
                        + idp.getIdentityProviderName());
            }

            extractGoogleParameters(authenticatorConfig, context);
            populateAuthenticatorContextProperties(context, authenticatorConfig);
            populateDebugSessionProperties(context, tenantDomain);
            return DebugContext.buildFromMap(context);
        } catch (ContextResolutionException e) {
            LOG.error("Error resolving Google debug context: " + e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            LOG.error("Unexpected error resolving Google debug context: " + e.getMessage(), e);
            throw new ContextResolutionException("CTX-50001", "Error resolving Google debug context",
                    e.getMessage(), e);
        }
    }

    @Override
    public boolean canHandle(Map<String, Object> params) {

        String connectionId = (String) params.get(CONNECTION_ID_KEY);
        try {
            if (StringUtils.isEmpty(connectionId)) {
                return false;
            }
            String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
            IdentityProvider idp = retrieveIdentityProvider(connectionId, tenantDomain);
            return idp != null && idp.isEnable() && findGoogleAuthenticatorConfig(idp, null) != null;
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error checking if GoogleDebugContextProvider can handle IdP: " + connectionId, e);
            }
            return false;
        }
    }

    public static String extractScope(Map<String, String> authenticatorProperties) {

        String scope = OIDCConfigurationExtractor.findPropertyValue(
                authenticatorProperties, OIDCConfigurationExtractor.getScopePropertyNames());
        if (StringUtils.isNotEmpty(scope)) {
            return scope;
        }

        String additionalParams = authenticatorProperties.get(
                GoogleOAuth2AuthenticationConstant.ADDITIONAL_QUERY_PARAMS);
        if (StringUtils.isNotEmpty(additionalParams)) {
            scope = extractScopeFromQueryParams(additionalParams);
            if (StringUtils.isNotEmpty(scope)) {
                return scope;
            }
        }

        return GoogleOAuth2AuthenticationConstant.GOOGLE_SCOPE;
    }

    public static String extractScopeFromQueryParams(String queryParams) {

        if (StringUtils.isBlank(queryParams)) {
            return null;
        }

        try {
            String[] params = queryParams.split("&");
            for (String param : params) {
                if (param.startsWith("scope=")) {
                    return URLDecoder.decode(param.substring("scope=".length()), StandardCharsets.UTF_8.name());
                }
            }
        } catch (Exception e) {
            LOG.warn("Error extracting scope from AdditionalQueryParameters: " + queryParams, e);
        }
        return null;
    }

    private IdentityProvider retrieveIdentityProvider(String idpId, String tenantDomain)
            throws ContextResolutionException {

        try {
            IdentityProviderManager idpManager = IdentityProviderManager.getInstance();
            IdentityProvider idp = idpManager.getIdPByResourceId(idpId, tenantDomain, false);
            if (idp == null) {
                idp = idpManager.getIdPByName(idpId, tenantDomain, false);
            }
            if (idp == null) {
                throw new ContextResolutionException("CTX-40401", "IdP not found: " + idpId,
                        "Identity Provider with ID or name '" + idpId + "' does not exist.");
            }
            return idp;
        } catch (ContextResolutionException e) {
            throw e;
        } catch (IdentityProviderManagementException e) {
            throw new ContextResolutionException("CTX-40401", "IdP not found: " + idpId, e.getMessage(), e);
        }
    }

    private void validateIdpIsEnabled(IdentityProvider idp) throws ContextResolutionException {

        if (!idp.isEnable()) {
            throw new ContextResolutionException("IdP is not available: " + idp.getIdentityProviderName());
        }
    }

    private void populateIdpContextProperties(Map<String, Object> context, IdentityProvider idp) {

        context.put(OIDCDebugConstants.DEBUG_IDP_NAME, idp.getIdentityProviderName());
        context.put(OIDCDebugConstants.DEBUG_IDP_RESOURCE_ID,
                StringUtils.defaultIfEmpty(idp.getResourceId(), idp.getIdentityProviderName()));
        context.put(OIDCDebugConstants.DEBUG_IDP_DESCRIPTION, idp.getIdentityProviderDescription());
        context.put(OIDCDebugConstants.IDP_CONFIG, idp);
    }

    private FederatedAuthenticatorConfig findGoogleAuthenticatorConfig(IdentityProvider idp,
            String authenticatorName) {

        FederatedAuthenticatorConfig[] configs = idp.getFederatedAuthenticatorConfigs();
        if (configs == null || configs.length == 0) {
            return null;
        }

        if (StringUtils.isNotEmpty(authenticatorName)) {
            for (FederatedAuthenticatorConfig config : configs) {
                if (config != null && config.isEnabled() && authenticatorName.equals(config.getName())) {
                    return config;
                }
            }
        }

        for (FederatedAuthenticatorConfig config : configs) {
            if (config == null || !config.isEnabled() || StringUtils.isEmpty(config.getName())) {
                continue;
            }
            if (GoogleOAuth2AuthenticationConstant.GOOGLE_CONNECTOR_NAME.equals(config.getName())) {
                return config;
            }
        }

        return null;
    }

    private void extractGoogleParameters(FederatedAuthenticatorConfig config, Map<String, Object> context)
            throws ContextResolutionException {

        Property[] properties = config.getProperties();
        if (properties == null || properties.length == 0) {
            throw new ContextResolutionException("No properties found in authenticator configuration");
        }

        Map<String, String> propertyMap = OIDCConfigurationExtractor.buildPropertyMap(properties);
        GoogleExecutor executor = new GoogleExecutor();

        String clientId = OIDCConfigurationExtractor.findPropertyValue(
                propertyMap, OIDCConfigurationExtractor.getClientIdPropertyNames());
        if (StringUtils.isEmpty(clientId)) {
            throw new ContextResolutionException("Client ID not found in authenticator configuration");
        }
        context.put(OIDCDebugConstants.CLIENT_ID, clientId);

        String authorizationEndpoint = executor.getAuthorizationServerEndpoint(propertyMap);
        if (StringUtils.isEmpty(authorizationEndpoint)) {
            throw new ContextResolutionException("Authorization endpoint not found in authenticator configuration");
        }
        context.put(OIDCDebugConstants.AUTHORIZATION_ENDPOINT, authorizationEndpoint);

        String tokenEndpoint = executor.getTokenEndpoint(propertyMap);
        if (StringUtils.isEmpty(tokenEndpoint)) {
            throw new ContextResolutionException("Token endpoint not found in authenticator configuration");
        }
        context.put(OIDCDebugConstants.TOKEN_ENDPOINT, tokenEndpoint);

        context.put(OIDCDebugConstants.IDP_SCOPE, extractScope(propertyMap));

        String clientSecret = OIDCConfigurationExtractor.findPropertyValue(
                propertyMap, OIDCConfigurationExtractor.getClientSecretPropertyNames());
        if (StringUtils.isNotEmpty(clientSecret)) {
            context.put(OIDCDebugConstants.CLIENT_SECRET, clientSecret);
        }

        String responseType = propertyMap.get("ResponseType");
        context.put(OIDCDebugConstants.RESPONSE_TYPE, StringUtils.isNotEmpty(responseType) ? responseType : "code");
        context.put(OIDCDebugConstants.PKCE_ENABLED, true);
        context.put(OIDCDebugConstants.PKCE_METHOD, OIDCDebugConstants.PKCE_METHOD_S256);
    }

    private void populateAuthenticatorContextProperties(Map<String, Object> context,
            FederatedAuthenticatorConfig authenticatorConfig) {

        context.put(OIDCDebugConstants.DEBUG_AUTHENTICATOR_NAME, authenticatorConfig.getName());
        context.put(OIDCDebugConstants.DEBUG_EXECUTOR_CLASS, GoogleExecutor.class.getName());
    }

    private void populateDebugSessionProperties(Map<String, Object> context, String tenantDomain) {

        context.put(OIDCDebugConstants.IS_DEBUG_FLOW, Boolean.TRUE);
        context.put(OIDCDebugConstants.DEBUG_ID, "debug-" + UUID.randomUUID());
        context.put(OIDCDebugConstants.DEBUG_TIMESTAMP, System.currentTimeMillis());
        context.put(OIDCDebugConstants.DEBUG_TENANT_DOMAIN, tenantDomain);
        context.put(OIDCDebugConstants.CONTEXT_PROTOCOL, OIDCDebugConstants.PROTOCOL_TYPE);
    }
}
