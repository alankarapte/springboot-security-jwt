package com.example.springsecurityjwt.models;


public class AuthenticationRequest {
	private String username;
	private String password;
	
	public AuthenticationRequest() {
		super();
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
