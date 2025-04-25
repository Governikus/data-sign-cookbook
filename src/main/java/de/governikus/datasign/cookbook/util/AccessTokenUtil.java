package de.governikus.datasign.cookbook.util;

import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;

import java.net.URI;
import java.util.Properties;

/**
 * We use the <a href="https://connect2id.com/products/nimbus-oauth-openid-connect-sdk">Nimbus OAuth 2.0 SDK</a>
 * to retrieve access tokens for the OAuth 2.0 authenticated REST API endpoints.
 * Using the Nimbus OAuth 2.0 SDK is optional and any other way to retrieve access tokens is fine.
 */
public class AccessTokenUtil {

    public static AccessToken retrieveAccessToken(Properties props) throws Exception {
        var request = new TokenRequest(
                new URI(props.getProperty("keycloak.issuerUri") + "/protocol/openid-connect/token"),
                new ClientSecretBasic(
                        new ClientID(props.getProperty("keycloak.clientId")),
                        new Secret(props.getProperty("keycloak.clientSecret"))),
                new ClientCredentialsGrant(),
                null);

        var tokenResponse = OIDCTokenResponseParser.parse(request.toHTTPRequest().send());

        if (!tokenResponse.indicatesSuccess()) {
            throw new RuntimeException(tokenResponse.toErrorResponse().getErrorObject().toString());
        }

        return tokenResponse.toSuccessResponse().getTokens().getAccessToken();
    }
}
