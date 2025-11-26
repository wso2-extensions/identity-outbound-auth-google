/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.google.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.google.GoogleExecutor;
import org.wso2.carbon.identity.application.authenticator.google.GoogleOAuth2Authenticator;
import org.wso2.carbon.identity.application.authenticator.google.debug.GoogleDebugProtocolProvider;
import org.wso2.carbon.identity.debug.framework.core.DebugProtocolProvider;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;

/**
 * OSGi declarative service component for Google OAuth2 Authenticator.
 * Registers the Google authenticator, executor, and debug protocol provider.
 */
@Component(
        name = "identity.application.authenticator.google.component",
        immediate = true
)
public class SocialAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(SocialAuthenticatorServiceComponent.class);

    /**
     * Activates the Google Social Authenticator Service Component.
     *
     * @param ctxt The component context.
     */
    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            GoogleOAuth2Authenticator googleAuthenticator = new GoogleOAuth2Authenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    googleAuthenticator, null);

            GoogleExecutor googleExecutor = new GoogleExecutor();
            ctxt.getBundleContext().registerService(Executor.class.getName(), googleExecutor, null);

            // Register Google Debug Protocol Provider.
            GoogleDebugProtocolProvider googleDebugProvider = new GoogleDebugProtocolProvider();
            ctxt.getBundleContext().registerService(DebugProtocolProvider.class.getName(),
                    googleDebugProvider, null);
            
            if (log.isDebugEnabled()) {
                log.debug("Google Debug Protocol Provider registered successfully for protocol: " 
                        + googleDebugProvider.getProtocolType());
            }

            if (log.isDebugEnabled()) {
                log.debug("Google Social Authenticator bundle is activated.");
            }

        } catch (Exception e) {
            log.error("Error while activating Google Social authenticator bundle: " + e.getMessage(), e);
        }
    }

    /**
     * Deactivates the Google Social Authenticator Service Component.
     *
     * @param ctxt The component context.
     */
    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("Google Social Authenticator bundle is deactivated.");
        }
    }
}
