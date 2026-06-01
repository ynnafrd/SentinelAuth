package com.sentinelauth.security.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * TokenDtos - Fase 4 (Transferência de Dados de Autenticação)
 * * Centraliza os modelos de dados usados para as operações de rotação de sessão.
 */
public class RefreshTokenDtos {
	
	public static class RefreshRequest {
		@NotBlank(message = "O Refresh Token de origem é obrigatório.")
		private String refreshToken;
		
		public String getRefreshToken() { return refreshToken; }
		public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
	}
	
	public static class TokenResponse {
		private String accessToken;
		private String refreshToken;
		private String tokenType = "Bearer";
		
		public TokenResponse(String accessToken, String refreshToken) {
			this.accessToken = accessToken;
			this.refreshToken = refreshToken;
		}
		
		public String getAccessToken() { return accessToken; }
		public String getRefreshToken() { return refreshToken; }
		public String getTokenType() { return tokenType; }
	}
}
