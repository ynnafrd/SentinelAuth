package com.sentinelauth.security.services;

import org.springframework.stereotype.Service;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * MfaService - Gestor de códigos OTP via Email.
 * * AppSec Strategy: Códigos aleatórios de uso único com expiração curta.
 */
@Service
public class MfaService {
	
	private final SecureRandom secureRandom = new SecureRandom();
	
	// Armazena temporariamente os códigos gerados (Código -> Expiração)
	// Em produção, isto deveria estar na tabela User ou no Redis com TTL.
	private final Map<String, OtpData> otpStorage = new ConcurrentHashMap<>();
	
	private static class OtpData {
		String code;
		Instant expiry;
		String email;
		
		OtpData(String code, Instant expiry, String email) {
			this.code = code;
			this.expiry = expiry;
			this.email = email;
		}
	}
	
	/**
	 * Gera um código de 6 dígitos e define validade de 5 minutos.
	 */
	public String generateEmailCode(String email) {
		String code = String.format("%06d", secureRandom.nextInt(1000000));
		otpStorage.put(email, new OtpData(code, Instant.now().plusSeconds(300), email));
		return code;
	}
	
	/**
	 * Valida o código enviado pelo utilizador.
	 */
	public boolean verifyCode(String email, String userInputCode) {
		OtpData data = otpStorage.get(email);
		
		if (data == null) return false;
		
		// Verifica expiração
		if (Instant.now().isAfter(data.expiry)) {
			otpStorage.remove(email);
			return false;
		}
		
		boolean isValid = data.code.equals(userInputCode);
		
		if (isValid) {
			otpStorage.remove(email); // Código de uso único (Burn after use)
		}
		
		return isValid;
	}
}