package com.dpt.demo;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Demo of OAuth2 flow in Cognito
 * for exchanging authenticationCode for token
 * via Http call
 * @author Deepthi
 */
public class AuthGrantFlow extends BaseClass {

	public static void main(String[] args) throws IOException {

		String authenticationCode = "97f5467f-5c19-489f-a981-7d9c862d0396";

		URL url = new URL(COGNITO_URL);
		HttpURLConnection connection = (HttpURLConnection) url.openConnection();
		connection.setRequestMethod("POST");
		connection.setDoOutput(true);
		connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		connection.setRequestProperty("charset", "utf-8");

		String inputParameters = "grant_type=authorization_code&client_id=" + APP_CLIENT_ID +
				"&redirect_uri=" + REDIRECT_URI + "&code=" + authenticationCode;

		byte[] postData = inputParameters.getBytes( StandardCharsets.UTF_8 );

		try(DataOutputStream wr = new DataOutputStream(connection.getOutputStream())) {
			wr.write( postData );
		}

		int responseCode = connection.getResponseCode();
		System.out.println(responseCode);
		String output = getResponseText(connection);
		JSONObject jsonObject = new JSONObject(output);
		System.out.println("REFRESH TOKEN = " + (String) jsonObject.get("refresh_token") );
		System.out.println("ID TOKEN = " + (String) jsonObject.get("id_token") );

	}

	private static String getResponseText(HttpURLConnection connection) throws IOException {
		String ret;
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
			StringBuilder buffer = new StringBuilder();
			String line;
			while ((line = reader.readLine()) != null) {
				buffer.append(line);
			}
			ret = buffer.toString();
		}
		return ret;
	}
}
