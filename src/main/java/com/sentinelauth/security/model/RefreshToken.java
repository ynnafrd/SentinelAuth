package com.sentinelauth.security.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {
	
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private UUID id;
	
	@NotNull
	@Column(nullable = false, unique = true)
	private String token;
	
	@NotNull
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "user_id", nullable = false)
	private User user;
	
	@NotNull
	@Column(nullable = false)
	private Instant expiryDate;
	
	@Column(nullable = false)
	private boolean revoked = false;
	
	@Column(nullable = false)
	private boolean used = false;
	
	// Construtores
	public RefreshToken() {}
	
	public RefreshToken(String token, User user, Instant expiryDate) {
		this.token = token;
		this.user = user;
		this.expiryDate = expiryDate;
	}
	
	// Métodos Auxiliares de Segurança
	public boolean isExpired() {
		return Instant.now().isAfter(this.expiryDate);
	}
	
	// Getters e Setters
	public UUID getId() { return id; }
	public String getToken() { return token; }
	public void setToken(String token) { this.token = token; }
	public User getUser() { return user; }
	public void setUser(User user) { this.user = user; }
	public Instant getExpiryDate() { return expiryDate; }
	public void setExpiryDate(Instant expiryDate) { this.expiryDate = expiryDate; }
	public boolean isRevoked() { return revoked; }
	public void setRevoked(boolean revoked) { this.revoked = revoked; }
	public boolean isUsed() { return used; }
	public void setUsed(boolean used) { this.used = used; }
}