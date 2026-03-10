package com.sentinelauth.security.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL) // Oculta campos nulos do JSON final
public class LoginResponseDTO {
	
	private String accessToken;
	private String refreshToken;
	private boolean mfaRequired;
	private String tempToken; // Token efêmero usado apenas para validar o TOTP
	
	public LoginResponseDTO() {}
	
	public static LoginResponseDTO success(String accessToken, String refreshToken) {
		LoginResponseDTO dto = new LoginResponseDTO();
		dto.accessToken = accessToken;
		dto.refreshToken = refreshToken;
		dto.mfaRequired = false;
		return dto;
	}
	
	public static LoginResponseDTO mfaPending(String tempToken) {
		LoginResponseDTO dto = new LoginResponseDTO();
		dto.mfaRequired = true;
		dto.tempToken = tempToken;
		return dto;
	}
	
	// Getters e Setters
	public String getAccessToken() { return accessToken; }
	public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
	public String getRefreshToken() { return refreshToken; }
	public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
	public boolean isMfaRequired() { return mfaRequired; }
	public void setMfaRequired(boolean mfaRequired) { this.mfaRequired = mfaRequired; }
	public String getTempToken() { return tempToken; }
	public void setTempToken(String tempToken) { this.tempToken = tempToken; }
}