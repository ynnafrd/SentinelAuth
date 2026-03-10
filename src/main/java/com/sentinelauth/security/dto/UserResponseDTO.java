package com.sentinelauth.security.dto;

import java.util.UUID;

public class UserResponseDTO {
	private UUID id;
	private String email;
	private String role;
	
	public UserResponseDTO(UUID id, String email, String role) {
		this.id = id;
		this.email = email;
		this.role = role;
	}
	
	// Apenas Getters são necessários para serialização JSON
	public UUID getId() { return id; }
	public String getEmail() { return email; }
	public String getRole() { return role; }
}