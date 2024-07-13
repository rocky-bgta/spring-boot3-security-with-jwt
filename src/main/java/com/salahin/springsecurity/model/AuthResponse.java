package com.salahin.springsecurity.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthResponse {

	private String token_type;
	private String expires_in;
	private String access_token;
	private String refresh_token;
}
