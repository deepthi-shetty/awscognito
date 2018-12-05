package com.dpt.demo;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClient;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.*;
import com.amazonaws.util.Base64;
import com.amazonaws.util.StringUtils;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class SigninFlowWithClientSecret extends BaseClass {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {

		final AWSCognitoIdentityProviderClient cognitoClient = (AWSCognitoIdentityProviderClient) AWSCognitoIdentityProviderClientBuilder.defaultClient();

		Map<String, String> loginMap = new HashMap<String, String>();
		loginMap.put("USERNAME", USER_ID);
		loginMap.put("PASSWORD", PASSWORD);
		loginMap.put("SECRET_HASH", getSecretHash(USER_ID, APP_CLIENT_ID, APP_CLIENT_SECRET));

		AdminInitiateAuthRequest loginRequest = new AdminInitiateAuthRequest()
				.withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
				.withClientId(APP_CLIENT_ID)
				.withUserPoolId(USER_POOL_ID)
				.withAuthParameters(loginMap);

		AdminInitiateAuthResult adminInitiateAuthResult = cognitoClient.adminInitiateAuth(loginRequest);
		AuthenticationResultType authenticationResultType;

		if (ChallengeNameType.NEW_PASSWORD_REQUIRED.name().equals(adminInitiateAuthResult.getChallengeName())) {
			Map<String, String> challengeResponseMap = new HashMap<String, String>();
			challengeResponseMap.put("USERNAME", USER_ID);
			challengeResponseMap.put("NEW_PASSWORD", PASSWORD);
			challengeResponseMap.put("SECRET_HASH", getSecretHash(USER_ID, APP_CLIENT_ID, APP_CLIENT_SECRET));

			AdminRespondToAuthChallengeRequest authChallengeRequest = new AdminRespondToAuthChallengeRequest()
					.withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
					.withChallengeResponses(challengeResponseMap)
					.withUserPoolId(USER_POOL_ID)
					.withClientId(APP_CLIENT_ID)
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
		refreshMap.put("SECRET_HASH", getSecretHash(USER_ID, APP_CLIENT_ID, APP_CLIENT_SECRET));

		AdminInitiateAuthRequest refreshRequest = new AdminInitiateAuthRequest()
				.withAuthFlow(AuthFlowType.REFRESH_TOKEN_AUTH)
				.withClientId(APP_CLIENT_ID)
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

	public static String getSecretHash(String userId, String clientId, String clientSecret) throws InvalidKeyException, NoSuchAlgorithmException {
		final String HMAC_SHA_256 = "HmacSHA256";
		SecretKeySpec signingKey = new SecretKeySpec(clientSecret.getBytes(StringUtils.UTF8), HMAC_SHA_256);
		Mac mac = Mac.getInstance(HMAC_SHA_256);
		mac.init(signingKey);
		mac.update(userId.getBytes(StringUtils.UTF8));
		byte[] rawHmac = mac.doFinal(clientId.getBytes(StringUtils.UTF8));
		return new String(Base64.encode(rawHmac));
	}
}
