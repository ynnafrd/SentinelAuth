package com.sentinelauth.security.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class LoginRequestDTO {
	
	@NotBlank(message = "O email é obrigatório")
	@Email(message = "Formato de email inválido")
	private String email;
	
	@NotBlank(message = "A senha é obrigatória")
	private String password;
	
	// Getters e Setters
	public String getEmail() { return email; }
	public void setEmail(String email) { this.email = email; }
	public String getPassword() { return password; }
	public void setPassword(String password) { this.password = password; }
}