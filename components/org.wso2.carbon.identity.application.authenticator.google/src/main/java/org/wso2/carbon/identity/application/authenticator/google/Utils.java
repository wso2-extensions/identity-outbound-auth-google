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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

/**
 * This is a utility classes for Google authenticator.
 */
public class Utils {

    private static final List<String> ISSUER = Arrays.asList("https://accounts.google.com", "accounts.google.com");
    private static final String JWS_RS256_URI = "https://www.googleapis.com/oauth2/v3/certs";
    private static final String JWS_ES256_URI = "https://www.gstatic.com/iap/verify/public_key-jwk";

    private Utils() {

    }

    /**
     * This function validates the JWT token by its content using nimbus libraries.
     *
     * @param idToken  String. The jwt token string.
     * @param audience String. Authenticator client ID to check validity.
     * @return boolean. Validity of the JWT token returned via Google One Tap.
     * @throws AuthenticationFailedException When JWT processor throws an exception.
     */
    public static boolean validateGoogleJWT(String idToken, String audience)
            throws AuthenticationFailedException {

        // Setting up the processor to verify the signature.
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(generateKeySelector(idToken));

        // Process the token.
        JWTClaimsSet claimsSet;
        try {
            claimsSet = jwtProcessor.process(idToken, null);
        } catch (ParseException | BadJOSEException | JOSEException e) {
            throw new AuthenticationFailedException(GoogleErrorConstants.ErrorMessages
                    .JWT_PROCESS_ERROR.getCode(), e.getMessage());
        }

        // Verifying the issuers and audiences.
        if (claimsSet != null && claimsSet.toJSONObject() != null && !claimsSet.toJSONObject().isEmpty()) {
            return ISSUER.contains(claimsSet.getIssuer()) && claimsSet.getAudience().contains(audience);
        }

        return false;
    }

    /**
     * This function generates the JWSKeySelector according to the hashing algorithm in the jwt token.
     *
     * @param idToken String The JWT token.
     * @return JWSKeySelector<SecurityContext> The generated key selector according to the hashing algorithm.
     * @throws AuthenticationFailedException When exceptions are thrown at parsing.
     */
    private static JWSKeySelector<SecurityContext> generateKeySelector(String idToken)
            throws AuthenticationFailedException {

        JWSKeySelector<SecurityContext> jwsKeySelector;
        JWT jwt;
        try {
            jwt = JWTParser.parse(idToken);
        } catch (ParseException e) {
            throw new AuthenticationFailedException(GoogleErrorConstants.ErrorMessages.JWT_PARSE_ERROR.getCode(),
                    e.getMessage());
        }
        // Class cast exception is handled while parsing the idToken.
        JWSAlgorithm expectedAlgorithm = (JWSAlgorithm) jwt.getHeader().getAlgorithm();
        String jwkSourceUrl = null;

        if (JWSAlgorithm.RS256.equals(expectedAlgorithm)) {
            jwkSourceUrl = JWS_RS256_URI;
        } else if (JWSAlgorithm.ES256.equals(expectedAlgorithm)) {
            jwkSourceUrl = JWS_ES256_URI;
        }

        if (jwkSourceUrl == null) {
            throw new AuthenticationFailedException(GoogleErrorConstants.ErrorMessages
                    .INVALID_JWK_SOURCE_URL.getCode(), String.format(GoogleErrorConstants.ErrorMessages
                    .INVALID_JWK_SOURCE_URL.getMessage(), jwkSourceUrl));
        }

        try {
            jwsKeySelector =
                    new JWSVerificationKeySelector<>(expectedAlgorithm, new RemoteJWKSet<>(new URL(jwkSourceUrl)));
        } catch (MalformedURLException e) {
            throw new AuthenticationFailedException(GoogleErrorConstants.ErrorMessages
                    .INVALID_JWK_SOURCE_URL.getCode(), String.format(GoogleErrorConstants.ErrorMessages
                    .INVALID_JWK_SOURCE_URL.getMessage(), jwkSourceUrl));
        }
        return jwsKeySelector;
    }
}
