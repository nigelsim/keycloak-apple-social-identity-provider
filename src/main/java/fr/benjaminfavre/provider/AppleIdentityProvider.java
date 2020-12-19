package fr.benjaminfavre.provider;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.ServerECDSASignatureSignerContext;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.*;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.util.JsonSerialization;
import org.keycloak.vault.VaultStringSecret;

import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class AppleIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig> {
    private String userJson;

    public AppleIdentityProvider(KeycloakSession session, AppleIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl("https://appleid.apple.com/auth/authorize?response_mode=form_post");
        config.setTokenUrl("https://appleid.apple.com/auth/token");
        config.setJwksUrl("https://appleid.apple.com/auth/token");
        config.setValidateSignature(true);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new OIDCEndpoint(callback, realm, event);
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        logger.debug("getFederatedIdentity, response:"+ response);

        BrokeredIdentityContext context = super.getFederatedIdentity(response);

        if (userJson != null) {
            try {
                logger.debug("getFederatedIdentity, userJson:"+ userJson);
                User user = JsonSerialization.readValue(userJson, User.class);
                context.setUsername(user.email);
                context.setEmail(user.email);
                context.setFirstName(user.name.firstName);
                context.setLastName(user.name.lastName);
            } catch (IOException e) {
                logger.errorf("Failed to parse userJson [%s]: %s", userJson, e);
            }
        }

        return context;
    }

    @Override
    public SimpleHttp authenticateTokenRequest(SimpleHttp tokenRequest) {
        AppleIdentityProviderConfig config = (AppleIdentityProviderConfig) getConfig();
        tokenRequest.param(OAUTH2_PARAMETER_CLIENT_ID, config.getClientId());
        String base64PrivateKey = config.getClientSecret();

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            byte[] pkc8ePrivateKey = Base64.getDecoder().decode(base64PrivateKey);
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(pkc8ePrivateKey);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpecPKCS8);

            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setAlgorithm(Algorithm.ES256);
            keyWrapper.setKid(config.getKeyId());
            keyWrapper.setPrivateKey(privateKey);
            SignatureSignerContext signer = new ServerECDSASignatureSignerContext(keyWrapper);

            long currentTime = Time.currentTime();
            JsonWebToken token = new JsonWebToken();
            token.issuer(config.getTeamId());
            token.iat(currentTime);
            token.exp(currentTime + 15 * 60);
            token.audience("https://appleid.apple.com");
            token.subject(config.getClientId());
            String clientSecret = new JWSBuilder().jsonContent(token).sign(signer);

            tokenRequest.param(OAUTH2_PARAMETER_CLIENT_SECRET, clientSecret);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.errorf("Failed to generate client secret: %s", e);
        }

        return tokenRequest;
    }

    @Override
    protected String getDefaultScopes() {
        return "email name";
    }

    protected class OIDCEndpoint extends OIDCIdentityProvider.OIDCEndpoint {
        public OIDCEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            super(callback, realm, event);
        }

        @POST
        public Response authResponse(
                @FormParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                @FormParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                @FormParam("user") String userJson,
                @FormParam(OAuth2Constants.ERROR) String error) {
            AppleIdentityProvider.this.userJson = userJson;
            return super.authResponse(state, authorizationCode, error);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class User {
        public String email;
        public Name name;

        @JsonIgnoreProperties(ignoreUnknown = true)
        private static class Name {
            public String firstName;
            public String lastName;
        }
    }

// override method to add logs
    @Override
    protected Response exchangeStoredToken(UriInfo uriInfo, EventBuilder event, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
        logger.debug("exchangeStoredToken");
        FederatedIdentityModel model = session.users().getFederatedIdentity(tokenSubject, getConfig().getAlias(), authorizedClient.getRealm());
        if (model == null || model.getToken() == null) {
            logger.error( "requested_issuer is not linked");
            event.detail(Details.REASON, "requested_issuer is not linked");
            event.error(Errors.INVALID_TOKEN);
            return exchangeNotLinked(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
        }
        try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(getConfig().getClientSecret())) {
            String modelTokenString = model.getToken();
            logger.debug("modelTokenString:"+modelTokenString);
            AccessTokenResponse tokenResponse = JsonSerialization.readValue(modelTokenString, AccessTokenResponse.class);
            Integer exp = (Integer) tokenResponse.getOtherClaims().get(ACCESS_TOKEN_EXPIRATION);
            logger.debug("ACCESS_TOKEN_EXPIRATION:"+exp.toString());
            if (exp != null && exp < Time.currentTime()) {
                if (tokenResponse.getRefreshToken() == null) {
                    return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
                }
                String response = getRefreshTokenRequest(session, tokenResponse.getRefreshToken(),
                        getConfig().getClientId(), vaultStringSecret.get().orElse(getConfig().getClientSecret())).asString();
                logger.debug("getRefreshTokenRequest : "+response);
                if (response.contains("error")) {
                    logger.debugv("Error refreshing token, refresh token expiration?: {0}", response);
                    model.setToken(null);
                    session.users().updateFederatedIdentity(authorizedClient.getRealm(), tokenSubject, model);
                    event.detail(Details.REASON, "requested_issuer token expired");
                    event.error(Errors.INVALID_TOKEN);
                    return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
                }
                AccessTokenResponse newResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
                if (newResponse.getExpiresIn() > 0) {
                    int accessTokenExpiration = Time.currentTime() + (int) newResponse.getExpiresIn();
                    newResponse.getOtherClaims().put(ACCESS_TOKEN_EXPIRATION, accessTokenExpiration);
                }

                if (newResponse.getRefreshToken() == null && tokenResponse.getRefreshToken() != null) {
                    newResponse.setRefreshToken(tokenResponse.getRefreshToken());
                    newResponse.setRefreshExpiresIn(tokenResponse.getRefreshExpiresIn());
                }
                response = JsonSerialization.writeValueAsString(newResponse);
                logger.debug("getRefreshTokenRequest : "+response);

                String oldToken = tokenUserSession.getNote(FEDERATED_ACCESS_TOKEN);
                if (oldToken != null && oldToken.equals(tokenResponse.getToken())) {
                    int accessTokenExpiration = newResponse.getExpiresIn() > 0 ? Time.currentTime() + (int) newResponse.getExpiresIn() : 0;
                    tokenUserSession.setNote(FEDERATED_TOKEN_EXPIRATION, Long.toString(accessTokenExpiration));
                    tokenUserSession.setNote(FEDERATED_REFRESH_TOKEN, newResponse.getRefreshToken());
                    tokenUserSession.setNote(FEDERATED_ACCESS_TOKEN, newResponse.getToken());
                    tokenUserSession.setNote(FEDERATED_ID_TOKEN, newResponse.getIdToken());

                }
                model.setToken(response);
                tokenResponse = newResponse;
            } else if (exp != null) {
                tokenResponse.setExpiresIn(exp - Time.currentTime());
            }
            tokenResponse.setIdToken(null);
            tokenResponse.setRefreshToken(null);
            tokenResponse.setRefreshExpiresIn(0);
            tokenResponse.getOtherClaims().clear();
            tokenResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
            tokenResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
            logger.debug("refreshToken, success");
            event.success();
            return Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    protected BrokeredIdentityContext exchangeExternalUserInfoValidationOnly(EventBuilder event, MultivaluedMap<String, String> params) {
        logger.debug("exchangeExternalUserInfoValidationOnly");
        String subjectToken = params.getFirst(OAuth2Constants.SUBJECT_TOKEN);
        logger.debug("subjectToken="+subjectToken);
        if (subjectToken == null) {
            event.detail(Details.REASON, OAuth2Constants.SUBJECT_TOKEN + " param unset");
            event.error(Errors.INVALID_TOKEN);
            throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "token not set", Response.Status.BAD_REQUEST);
        }
        String subjectTokenType = params.getFirst(OAuth2Constants.SUBJECT_TOKEN_TYPE);
        logger.debug("subjectTokenType="+subjectTokenType);
        if (subjectTokenType == null) {
            subjectTokenType = OAuth2Constants.ACCESS_TOKEN_TYPE;
        }
        if (!OAuth2Constants.ACCESS_TOKEN_TYPE.equals(subjectTokenType)) {
            event.detail(Details.REASON, OAuth2Constants.SUBJECT_TOKEN_TYPE + " invalid");
            event.error(Errors.INVALID_TOKEN_TYPE);
            throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token type", Response.Status.BAD_REQUEST);
        }
        return validateExternalTokenThroughUserInfo(event, subjectToken, subjectTokenType);
    }

    @Override
    public void exchangeExternalComplete(UserSessionModel userSession, BrokeredIdentityContext context, MultivaluedMap<String, String> params) {
        logger.debug("exchangeExternalComplete");
        if (context.getContextData().containsKey(OIDCIdentityProvider.VALIDATED_ID_TOKEN))
            userSession.setNote(FEDERATED_ACCESS_TOKEN, params.getFirst(OAuth2Constants.SUBJECT_TOKEN));
        if (context.getContextData().containsKey(OIDCIdentityProvider.VALIDATED_ID_TOKEN))
            userSession.setNote(OIDCIdentityProvider.FEDERATED_ID_TOKEN, params.getFirst(OAuth2Constants.SUBJECT_TOKEN));
        userSession.setNote(OIDCIdentityProvider.EXCHANGE_PROVIDER, getConfig().getAlias());

    }
    protected BrokeredIdentityContext validateExternalTokenThroughUserInfo(EventBuilder event, String subjectToken, String subjectTokenType) {
        logger.debug("validateExternalTokenThroughUserInfo");
        event.detail("validation_method", "user info");
        SimpleHttp.Response response = null;
        int status = 0;
        try {
            String userInfoUrl = getProfileEndpointForValidation(event);
            logger.debug("validateExternalTokenThroughUserInfo, userInfoUrl="+userInfoUrl);
            response = buildUserInfoRequest(subjectToken, userInfoUrl).asResponse();
            logger.debug("validateExternalTokenThroughUserInfo, response="+response);
            status = response.getStatus();
            logger.debug("validateExternalTokenThroughUserInfo, status="+status);
        } catch (IOException e) {
            logger.debug("Failed to invoke user info for external exchange", e);
        }
        if (status != 200) {
            logger.debug("Failed to invoke user info status: " + status);
            event.detail(Details.REASON, "user info call failure");
            event.error(Errors.INVALID_TOKEN);
            throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token", Response.Status.BAD_REQUEST);
        }
        JsonNode profile = null;
        try {
            profile = response.asJson();
        } catch (IOException e) {
            event.detail(Details.REASON, "user info call failure");
            event.error(Errors.INVALID_TOKEN);
            throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token", Response.Status.BAD_REQUEST);
        }
        BrokeredIdentityContext context = extractIdentityFromProfile(event, profile);
        if (context.getId() == null) {
            event.detail(Details.REASON, "user info call failure");
            event.error(Errors.INVALID_TOKEN);
            throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token", Response.Status.BAD_REQUEST);
        }
        return context;
    }

    @Override
    protected BrokeredIdentityContext exchangeExternalImpl(EventBuilder event, MultivaluedMap<String, String> params) {
        logger.debug("exchangeExternalImpl, params="+params);
        if (!supportsExternalExchange()) return null;
        String subjectToken = params.getFirst(OAuth2Constants.SUBJECT_TOKEN);
        logger.debug("exchangeExternalImpl, subjectToken="+subjectToken);
        if (subjectToken == null) {
            event.detail(Details.REASON, OAuth2Constants.SUBJECT_TOKEN + " param unset");
            event.error(Errors.INVALID_TOKEN);
            throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "token not set", Response.Status.BAD_REQUEST);
        }
        String subjectTokenType = params.getFirst(OAuth2Constants.SUBJECT_TOKEN_TYPE);
        logger.debug("exchangeExternalImpl, subjectTokenType="+subjectTokenType);
        if (subjectTokenType == null) {
            subjectTokenType = OAuth2Constants.ACCESS_TOKEN_TYPE;
        }
        logger.debug("validateJwt, getConfig().isValidateSignature()"+getConfig().isValidateSignature());
        logger.debug("validateJwt, getConfig().isUseJwksUrl()"+getConfig().isUseJwksUrl());
        logger.debug("validateJwt, getConfig().getPublicKeySignatureVerifier()"+getConfig().getPublicKeySignatureVerifier());

        if (OAuth2Constants.JWT_TOKEN_TYPE.equals(subjectTokenType) || OAuth2Constants.ID_TOKEN_TYPE.equals(subjectTokenType)) {
            logger.debug("exchangeExternalImpl, validateJwt");
            return validateJwt(event, subjectToken, subjectTokenType);
        } else if (OAuth2Constants.ACCESS_TOKEN_TYPE.equals(subjectTokenType)) {
            logger.debug("exchangeExternalImpl, validateExternalTokenThroughUserInfo");
            return validateExternalTokenThroughUserInfo(event, subjectToken, subjectTokenType);
        } else {
            event.detail(Details.REASON, OAuth2Constants.SUBJECT_TOKEN_TYPE + " invalid");
            event.error(Errors.INVALID_TOKEN_TYPE);
            throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token type", Response.Status.BAD_REQUEST);
        }
    }


    protected JsonWebToken validateToken(String encodedToken, boolean ignoreAudience) {
        logger.debug("validateToken, encodedToken="+encodedToken);
        if (encodedToken == null) {
            throw new IdentityBrokerException("No token from server.");
        }

        JsonWebToken token;
        try {
            JWSInput jws = new JWSInput(encodedToken);
            if (!verify(jws)) {
                throw new IdentityBrokerException("token signature validation failed");
            }
            token = jws.readJsonContent(JsonWebToken.class);
        } catch (JWSInputException e) {
            throw new IdentityBrokerException("Invalid token", e);
        }

        String iss = token.getIssuer();
        logger.debug("validateToken, iss="+iss);

        if (!token.isActive(getConfig().getAllowedClockSkew())) {
            throw new IdentityBrokerException("Token is no longer valid");
        }

        if (!ignoreAudience && !token.hasAudience(getConfig().getClientId())) {
            throw new IdentityBrokerException("Wrong audience from token.");
        }

        if (!ignoreAudience && (token.getIssuedFor() != null && !getConfig().getClientId().equals(token.getIssuedFor()))) {
            throw new IdentityBrokerException("Token issued for does not match client id");
        }

        String trustedIssuers = getConfig().getIssuer();
        logger.debug("validateToken, trustedIssuers="+trustedIssuers);

        if (trustedIssuers != null && trustedIssuers.length() > 0) {
            String[] issuers = trustedIssuers.split(",");

            for (String trustedIssuer : issuers) {
                if (iss != null && iss.equals(trustedIssuer.trim())) {
                    return token;
                }
            }

            throw new IdentityBrokerException("Wrong issuer from token. Got: " + iss + " expected: " + getConfig().getIssuer());
        }

        return token;
    }

}
