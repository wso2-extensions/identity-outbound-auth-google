/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
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

/**
 * This class defines all the error codes and messages which are specific for
 * Google authenticator.
 */
public class GoogleErrorConstants {

    public enum ErrorMessages {

        CSRF_VALIDATION_FAILED_ERROR("60000", "CSRF cookie validation failed in Google one tap. " +
                "Authenticator : %s Client Id : %s ."),
        TOKEN_VALIDATION_FAILED_ERROR("60001", "JWT validation failed in Google one tap. " +
                "Authenticator : %s Client Id : %s .");
        private final String code;
        private final String message;

        /**
         * The constructor to create an error constant using an error code and a message.
         *
         * @param code    Proper defined error code according to the standards.
         * @param message Descriptive error message.
         */
        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        /**
         * Returns the error code of the error constant.
         *
         * @return String The error code.
         */
        public String getCode() {

            return code;
        }

        /**
         * Returns the descriptive error message of the error constant.
         *
         * @return String The error message.
         */
        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return String.format("%s  - %s", code, message);
        }
    }
}
