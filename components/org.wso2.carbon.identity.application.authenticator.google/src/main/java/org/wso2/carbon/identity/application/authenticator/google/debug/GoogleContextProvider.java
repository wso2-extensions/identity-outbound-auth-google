/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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
import org.wso2.carbon.identity.application.authenticator.oidc.debug.OAuth2ContextProvider;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;

import java.util.Map;

/**
 * Google authenticator context provider for debug operations.
 * Extends OAuth2ContextProvider to add Google-specific context resolution.
 * Handles Google-specific property names and authenticator identification.
 */
public class GoogleContextProvider extends OAuth2ContextProvider {

    private static final Log LOG = LogFactory.getLog(GoogleContextProvider.class);

    /**
     * Validates if this resolver can handle the given IdP.
     * Returns true if the IdP has at least one enabled Google OAuth2 authenticator.
     *
     * @param idpId Identity Provider ID to check.
     * @return true if this resolver can handle Google IdP, false otherwise.
     */
    @Override
    public boolean canResolve(String idpId) {
        try {
            if (StringUtils.isEmpty(idpId)) {
                return false;
            }

            // First check if parent (OAuth2) can resolve it
            if (!super.canResolve(idpId)) {
                return false;
            }

            // Additional Google-specific check: verify it's a Google authenticator
            org.wso2.carbon.idp.mgt.IdentityProviderManager idpManager = 
                    org.wso2.carbon.idp.mgt.IdentityProviderManager.getInstance();
            IdentityProvider idp = null;
            String tenantDomain = org.wso2.carbon.identity.core.util.IdentityTenantUtil.resolveTenantDomain();

            try {
                idp = idpManager.getIdPByResourceId(idpId, tenantDomain, true);
            } catch (org.wso2.carbon.idp.mgt.IdentityProviderManagementException e) {
                try {
                    idp = idpManager.getIdPByName(idpId, tenantDomain);
                } catch (org.wso2.carbon.idp.mgt.IdentityProviderManagementException e2) {
                    return false;
                }
            }

            if (idp == null || !idp.isEnable()) {
                return false;
            }

            // Check if IdP has Google authenticator
            return findGoogleAuthenticatorConfig(idp) != null;
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error checking if GoogleContextProvider can handle IdP: " + e.getMessage());
            }
            return false;
        }
    }

    /**
     * Finds the Google authenticator configuration in the IdP.
     *
     * @param idp Identity Provider.
     * @return FederatedAuthenticatorConfig or null if not found.
     */
    private FederatedAuthenticatorConfig findGoogleAuthenticatorConfig(IdentityProvider idp) {
        FederatedAuthenticatorConfig[] configs = idp.getFederatedAuthenticatorConfigs();
        if (configs == null || configs.length == 0) {
            return null;
        }

        for (FederatedAuthenticatorConfig config : configs) {
            if (config == null || !config.isEnabled()) {
                continue;
            }
            String configName = config.getName();
            if (StringUtils.isEmpty(configName)) {
                continue;
            }

            // Match Google authenticators (case-sensitive)
            if (configName.equals("GoogleOAuth2Authenticator") || 
                configName.equals("GoogleOIDCAuthenticator") ||
                configName.equals("GoogleAuthenticator")) {
                return config;
            }
        }

        return null;
    }

    /**
     * Extracts scope from authenticator properties using multiple fallback strategies.
     * 
     * Strategy 1: Check standard scope properties (case-sensitive variations).
     * Strategy 2: Check AdditionalQueryParameters for scope (like Google OIDC uses).
     * Strategy 3: Check executor's getScope method if available.
     * Strategy 4: Default to "openid" if absolutely no scope found anywhere.
     *
     * @param authenticatorProperties Map containing authenticator configuration properties.
     * @param executor Optional executor instance that may have getScope method.
     * @return Resolved scope value, never null.
     */
    public static String extractScope(Map<String, String> authenticatorProperties, Object executor) {
        String scope = null;

        // Strategy 1: Check standard scope properties (case-sensitive variations).
        String[] scopePropertyNames = {"Scope", "scope", "SCOPE", "scopes", "requestedScope", 
                                       "requestedScopes"};
        for (String scopePropName : scopePropertyNames) {
            String scopeValue = authenticatorProperties.get(scopePropName);
            if (StringUtils.isNotEmpty(scopeValue)) {
                scope = scopeValue;
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found scope in property: " + scopePropName + " = " + scope);
                }
                break;
            }
        }
        
        // Strategy 2: Check AdditionalQueryParameters for scope (like Google OIDC uses).
        if (StringUtils.isEmpty(scope)) {
            String additionalParams = authenticatorProperties.get("AdditionalQueryParameters");
            if (additionalParams != null && !additionalParams.isEmpty()) {
                scope = extractScopeFromQueryParams(additionalParams);
                if (StringUtils.isNotEmpty(scope) && LOG.isDebugEnabled()) {
                    LOG.debug("Found scope in AdditionalQueryParameters: " + scope);
                }
            }
        }
        
        // Strategy 3: Check executor's getScope method if available.
        if (StringUtils.isEmpty(scope) && executor != null) {
            scope = invokeExecutorGetScope(executor, authenticatorProperties);
        }
        
        // Strategy 4: Only default to "openid" if absolutely no scope found anywhere.
        if (StringUtils.isEmpty(scope)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No scope found in configuration, defaulting to 'openid'");
            }
            scope = "openid";
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Final resolved scope: " + scope);
        }
        
        return scope;
    }

    /**
     * Extracts scope from authenticator properties using multiple fallback strategies.
     * This version does not require an executor instance.
     *
     * @param authenticatorProperties Map containing authenticator configuration properties.
     * @return Resolved scope value, never null.
     */
    public static String extractScope(Map<String, String> authenticatorProperties) {
        return extractScope(authenticatorProperties, null);
    }

    /**
     * Helper to extract scope from AdditionalQueryParameters.
     * Example: "scope=openid+email" or "scope=openid%20email".
     *
     * @param queryParams Query parameters string.
     * @return Extracted scope value or null if not found.
     */
    public static String extractScopeFromQueryParams(String queryParams) {
        if (queryParams == null || queryParams.trim().isEmpty()) {
            return null;
        }
        try {
            String[] params = queryParams.split("&");
            for (String param : params) {
                if (param.startsWith("scope=")) {
                    String scope = param.substring("scope=".length());
                    scope = java.net.URLDecoder.decode(scope, "UTF-8");
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Extracted scope from query params: " + scope);
                    }
                    return scope;
                }
            }
        } catch (Exception e) {
            LOG.warn("Error extracting scope from AdditionalQueryParameters: " + queryParams, e);
        }
        return null;
    }

    /**
     * Invokes executor's getScope method via reflection.
     * Returns null if method doesn't exist or invocation fails.
     *
     * @param executor Executor instance.
     * @param authenticatorProperties Authenticator properties map.
     * @return Scope from executor or null if not available.
     */
    private static String invokeExecutorGetScope(Object executor, Map<String, String> authenticatorProperties) {
        try {
            java.lang.reflect.Method method = executor.getClass().getMethod("getScope", Map.class);
            Object result = method.invoke(executor, authenticatorProperties);
            if (result != null && !result.toString().trim().isEmpty()) {
                String scope = result.toString();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found scope via executor.getScope(): " + scope);
                }
                return scope;
            }
        } catch (NoSuchMethodException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Executor does not have getScope(Map) method");
            }
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Failed to get scope from executor: " + e.getMessage());
            }
        }
        return null;
    }

    /**
     * Validates and normalizes scope string.
     *
     * @param scope Scope string to validate.
     * @return true if scope is valid and not empty, false otherwise.
     */
    public static boolean isValidScope(String scope) {
        return StringUtils.isNotEmpty(scope) && !scope.trim().isEmpty();
    }

    /**
     * Gets first non-empty value from property map for multiple key variants.
     *
     * @param map Property map.
     * @param keys Possible key names to check (in order).
     * @return First non-empty value or null.
     */
    public static String getOrNull(Map<String, String> map, String... keys) {
        if (map == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            String value = map.get(key);
            if (StringUtils.isNotEmpty(value)) {
                return value;
            }
        }
        return null;
    }
}
