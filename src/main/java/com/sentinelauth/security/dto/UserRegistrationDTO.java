package com.sentinelauth.security.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class UserRegistrationDTO {
	
	@NotBlank(message = "O email é obrigatório")
	@Email(message = "Formato de email inválido")
	private String email;
	
	/**
	 * AppSec: Política de Senhas Forte (Checkpoint 1)
	 * - Mínimo 8 caracteres (NIST guidelines recomendam tamanho sobre complexidade, mas vamos forçar ambos)
	 * - Pelo menos uma maiúscula, uma minúscula, um número e um caractere especial.
	 */
	@NotBlank(message = "A senha é obrigatória")
	@Size(min = 8, max = 128, message = "A senha deve ter entre 8 e 128 caracteres")
	@Pattern(
			regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).*$",
			message = "A senha deve conter maiúsculas, minúsculas, números e caracteres especiais"
	)
	private String password;
	
	// Getters e Setters
	public String getEmail() { return email; }
	public void setEmail(String email) { this.email = email; }
	public String getPassword() { return password; }
	public void setPassword(String password) { this.password = password; }
}