package com.salahin.springsecurity.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthResponse {

	private String token_type;
	private String expires_in;
	private String access_token;
	@JsonIgnore
	private String refresh_token;
}
