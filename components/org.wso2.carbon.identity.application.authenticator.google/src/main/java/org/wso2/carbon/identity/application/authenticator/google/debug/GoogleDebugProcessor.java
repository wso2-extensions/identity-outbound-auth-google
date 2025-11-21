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

import org.wso2.carbon.identity.application.authenticator.oidc.debug.OAuth2DebugProcessor;

/**
 * Google authenticator reuses OAuth2DebugProcessor directly.
 * Google uses standard OAuth2/OIDC protocol, so no Google-specific overrides are needed.
 * 
 * This is simply an alias for cleaner organization and future extensibility.
 * If Google-specific debug behavior is needed in the future, this class can be extended
 * with overrides while keeping the inheritance clean.
 *
 * Reuses: OAuth2 token exchange, claim extraction, debug result building, caching, etc.
 */
public class GoogleDebugProcessor extends OAuth2DebugProcessor {
    // No additional logic needed - Google uses standard OAuth2 protocol
}
