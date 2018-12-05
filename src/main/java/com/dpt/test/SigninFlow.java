package com.dpt.test;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClient;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.security.InvalidKeyException;
import java.util.HashMap;
import java.util.Map;

/**
 * This class demonstrates how to sign in using AdmintInitiateAuth flow.
 * Then receive the refresh token.
 * The refresh token can again be used to receive new tokens.
 * All the received tokens are decoded.
 * by @deepthi
 */
public class SigninFlow extends  BaseClass{

	public static void main(String[] args) {

		final AWSCognitoIdentityProviderClient cognitoClient = (AWSCognitoIdentityProviderClient) AWSCognitoIdentityProviderClientBuilder.defaultClient();

		Map<String, String> loginMap = new HashMap<String, String>();
		loginMap.put("USERNAME", USER_ID);
		loginMap.put("PASSWORD", PASSWORD);

		AdminInitiateAuthRequest loginRequest = new AdminInitiateAuthRequest()
				.withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
				.withClientId(APP_NOSECRET_CLIENT_ID)
				.withUserPoolId(USER_POOL_ID)
				.withAuthParameters(loginMap);

		AdminInitiateAuthResult adminInitiateAuthResult = cognitoClient.adminInitiateAuth(loginRequest);
		AuthenticationResultType authenticationResultType;

		if (ChallengeNameType.NEW_PASSWORD_REQUIRED.name().equals(adminInitiateAuthResult.getChallengeName())) {
			Map<String, String> challengeResponseMap = new HashMap<String, String>();
			challengeResponseMap.put("USERNAME", USER_ID);
			challengeResponseMap.put("NEW_PASSWORD", PASSWORD);

			AdminRespondToAuthChallengeRequest authChallengeRequest = new AdminRespondToAuthChallengeRequest()
					.withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
					.withChallengeResponses(challengeResponseMap)
					.withUserPoolId(USER_POOL_ID)
					.withClientId(APP_NOSECRET_CLIENT_ID)
					.withSession(adminInitiateAuthResult.getSession());
			AdminRespondToAuthChallengeResult authChallengeResponse = cognitoClient.adminRespondToAuthChallenge(authChallengeRequest);
			authenticationResultType = authChallengeResponse.getAuthenticationResult();
		} else {
			authenticationResultType = adminInitiateAuthResult.getAuthenticationResult();
		}

		System.out.println("id_token=" + authenticationResultType.getIdToken());
		System.out.println("access_token=" + authenticationResultType.getAccessToken());
		System.out.println("refresh_token=" + authenticationResultType.getRefreshToken());

		/* Decode the tokens received */
		DecodedJWT decodedIdJWT = JWT.decode(authenticationResultType.getIdToken());
		System.out.println(decodedIdJWT.getClaim("cognito:username").asString());
		System.out.println(decodedIdJWT.getClaim("email").asString());

		/**
		 * Getting new tokens with refresh token
		 */
		Map<String, String> refreshMap = new HashMap<String, String>();
		refreshMap.put("REFRESH_TOKEN", authenticationResultType.getRefreshToken());

		AdminInitiateAuthRequest refreshRequest = new AdminInitiateAuthRequest()
				.withAuthFlow(AuthFlowType.REFRESH_TOKEN_AUTH)
				.withClientId(APP_NOSECRET_CLIENT_ID)
				.withUserPoolId(USER_POOL_ID)
				.withAuthParameters(refreshMap);
		AdminInitiateAuthResult refreshResult = cognitoClient.adminInitiateAuth(refreshRequest);
		System.out.println("id_token=" + refreshResult.getAuthenticationResult().getIdToken());
		System.out.println("access_token=" + refreshResult.getAuthenticationResult().getAccessToken());
		System.out.println("refresh_token=" + refreshResult.getAuthenticationResult().getRefreshToken());

		DecodedJWT decodedIdJWT2 = JWT.decode(refreshResult.getAuthenticationResult().getIdToken());
		System.out.println(decodedIdJWT2.getClaim("cognito:username").asString());
		System.out.println(decodedIdJWT2.getClaim("email").asString());

		DecodedJWT decodedAccessToken = JWT.decode(refreshResult.getAuthenticationResult().getAccessToken());
		System.out.println(decodedAccessToken);

	}
}
