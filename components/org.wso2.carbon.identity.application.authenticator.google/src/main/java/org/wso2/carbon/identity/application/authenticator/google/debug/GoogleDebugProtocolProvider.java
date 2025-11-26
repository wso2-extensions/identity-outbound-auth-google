/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

import org.wso2.carbon.identity.debug.framework.core.DebugContextProvider;
import org.wso2.carbon.identity.debug.framework.core.DebugExecutor;
import org.wso2.carbon.identity.debug.framework.core.DebugProcessor;
import org.wso2.carbon.identity.debug.framework.core.DebugProtocolProvider;

/**
 * Google debug protocol provider implementation.
 * Registers Google-specific debug components with the debug framework.
 * 
 * <p>
 * This provider enables debug functionality for Google OAuth2/OIDC authentication flows
 * by supplying Google-specific implementations of context resolution, execution, and
 * callback processing.
 * </p>
 * 
 * @since 1.0.0
 */
public class GoogleDebugProtocolProvider implements DebugProtocolProvider {

    private static final String PROTOCOL_TYPE = "Google";

    /**
     * Gets the protocol type identifier for this provider.
     * 
     * @return "Google" - the protocol identifier.
     */
    @Override
    public String getProtocolType() {

        return PROTOCOL_TYPE;
    }

    /**
     * Gets the context provider for Google OAuth2 authentication.
     * The context provider resolves Google-specific OAuth2 configuration from IdP settings.
     *
     * @return GoogleContextProvider instance for resolving Google OAuth2 configuration.
     */
    @Override
    public DebugContextProvider getContextProvider() {

        return new GoogleContextProvider();
    }

    /**
     * Gets the executor for Google OAuth2 debug flow.
     * The executor generates Google OAuth2 authorization URLs with PKCE support.
     *
     * @return GoogleDebugExecuter instance for generating authorization URLs.
     */
    @Override
    public DebugExecutor getExecutor() {

        return new GoogleDebugExecuter();
    }

    /**
     * Gets the processor for Google OAuth2 callback handling.
     * The processor handles the callback after user authentication with Google,
     * exchanges authorization code for tokens, and extracts user claims.
     *
     * @return GoogleDebugProcessor instance for processing OAuth2 callbacks.
     */
    @Override
    public DebugProcessor getProcessor() {

        return new GoogleDebugProcessor();
    }

    /**
     * Determines if this provider can handle the given protocol type.
     * Supports "Google" protocol type.
     *
     * @param protocolType The protocol type to check.
     * @return true if protocolType is "Google" (case-insensitive), false otherwise.
     */
    @Override
    public boolean supports(String protocolType) {

        return PROTOCOL_TYPE.equalsIgnoreCase(protocolType);
    }
}
