/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.application.authenticator.google;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.List;
import java.util.Map;
import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

public class JsHookAuthenticator extends GoogleOAuth2Authenticator {

    private static Log log = LogFactory.getLog(JsHookAuthenticator.class);

    @Override
    public String getFriendlyName() {
        return "JsHookAuthenticator";
    }

    @Override
    public String getName() {
        return "JSHookAuthenticator";
    }

    @Override
    protected Map<ClaimMapping, String> getSubjectAttributes(OAuthClientResponse token, Map<String, String> authenticatorProperties) {
        Map<ClaimMapping, String> claimsMap = super.getSubjectAttributes(token, authenticatorProperties);

        // Call the JS Hook to play around with the claims
        try {
            this.JsHook(new ClaimMapWrapper(claimsMap));
        } catch (ScriptException | NoSuchMethodException | FileNotFoundException e) {
            log.error("Error evaluating jsHook.", e);
        }

        return claimsMap;
    }


    @Override
    public List<Property> getConfigurationProperties() {
        return super.getConfigurationProperties();
    }


    private void JsHook(ClaimMapWrapper claimMapWrapper) throws ScriptException, NoSuchMethodException, FileNotFoundException {

        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        engine.eval(new FileReader(getFilePath("jsHook.js")));

        Invocable invocable = (Invocable) engine;
        /*
            the js hook has a function with name 'handle' which takes the claimWrapper as the argument.
            var handle = function(claimWrapper) {};
         */
        invocable.invokeFunction("handle", claimMapWrapper);
    }


    /*
        We are expecting our js hook at IS_HOME/repository/conf/<filename>
     */
    private String getFilePath(String fileName) {
        return CarbonUtils.getCarbonConfigDirPath() + File.separator + fileName;
    }
}
