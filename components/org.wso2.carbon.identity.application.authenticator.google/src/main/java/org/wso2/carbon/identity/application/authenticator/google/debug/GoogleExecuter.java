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

import org.wso2.carbon.identity.application.authenticator.oidc.debug.OAuth2DebugExecuter;

/**
 * Google authenticator executor for debug operations.
 * Google uses standard OAuth2/OIDC protocol for authorization URL generation,
 * so it reuses the OAuth2 executor implementation without additional overrides.
 * 
 * This class follows the naming convention expected by DebugProtocolRouter:
 * {Protocol}Executer for protocol-specific implementations.
 * 
 * Reuses: OAuth2 authorization URL generation, PKCE support, state management, etc.
 */
public class GoogleExecuter extends OAuth2DebugExecuter {
    // No additional logic needed - Google uses standard OAuth2 protocol
}
