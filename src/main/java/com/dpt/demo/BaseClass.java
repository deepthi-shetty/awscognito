package com.dpt.demo;

import java.util.ResourceBundle;

/**
 * Holds properties for child classes to use
 */
public class BaseClass {
	private static ResourceBundle config = ResourceBundle.getBundle("config");

	public static final String USER_POOL_ID;
	public static final String APP_CLIENT_ID;
	public static final String APP_CLIENT_SECRET;
	public static final String APP_NOSECRET_CLIENT_ID;

	public static final String REDIRECT_URI;

	public static final String USER_ID;
	public static final String PASSWORD;


	static  {

		USER_POOL_ID = config.getString("user_pool_id");
		APP_CLIENT_ID = config.getString("app_client_id");
		APP_CLIENT_SECRET = config.getString("app_client_secret");
		APP_NOSECRET_CLIENT_ID = config.getString("app_no_secret_client_id");

		REDIRECT_URI = config.getString("cognito_redirect_uri");

		USER_ID = config.getString("test_user_id");
		PASSWORD = config.getString("test_password");
	}
}
