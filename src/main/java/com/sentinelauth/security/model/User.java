package com.sentinelauth.security.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;

/**
 * Entidade User - Atualizada para Fase 3 (MFA)
 * * AppSec Feature: Armazenamento de segredo TOTP.
 */
@Entity
@Table(name = "users")
public class User {
	
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private UUID id;
	
	@NotNull
	@Email
	@Column(unique = true, nullable = false)
	private String email;
	
	@NotNull
	@Column(nullable = false)
	private String passwordHash;
	
	private String role;
	
	// --- NOVOS CAMPOS MFA ---
	
	@Column(name = "mfa_enabled")
	private boolean mfaEnabled = false;
	
	@Column(name = "mfa_secret")
	private String mfaSecret; // Chave secreta Base32 para o Google Authenticator
	
	// Construtores
	public User() {}
	
	public User(String email, String passwordHash, String role) {
		this.email = email;
		this.passwordHash = passwordHash;
		this.role = role;
	}
	
	// Getters e Setters
	public UUID getId() { return id; }
	public String getEmail() { return email; }
	public void setEmail(String email) { this.email = email; }
	public String getPasswordHash() { return passwordHash; }
	public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
	public String getRole() { return role; }
	public void setRole(String role) { this.role = role; }
	
	public boolean isMfaEnabled() { return mfaEnabled; }
	public void setMfaEnabled(boolean mfaEnabled) { this.mfaEnabled = mfaEnabled; }
	public String getMfaSecret() { return mfaSecret; }
	public void setMfaSecret(String mfaSecret) { this.mfaSecret = mfaSecret; }
}