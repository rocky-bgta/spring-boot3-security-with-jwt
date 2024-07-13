package com.salahin.springsecurity.model;

import lombok.Data;

@Data
public class AuthRequest {

	private String username;
	private String password;

	public AuthRequest(String username, String password) {
		this.username = username;
		this.password = password;
	}

	public AuthRequest() {
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}
