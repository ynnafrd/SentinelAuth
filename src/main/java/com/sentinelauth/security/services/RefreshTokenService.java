package com.sentinelauth.security.services;

import com.sentinelauth.security.exceptions.TokenRefreshException;
import com.sentinelauth.security.model.RefreshToken;
import com.sentinelauth.security.repository.RefreshTokenRepository;
import com.sentinelauth.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService {
	
	@Value("${jwt.refreshExpiration}")
	private Long refreshTokenDurationMs;
	
	private final RefreshTokenRepository refreshTokenRepository;
	private final UserRepository userRepository;
	
	public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UserRepository userRepository) {
		this.refreshTokenRepository = refreshTokenRepository;
		this.userRepository = userRepository;
	}
	
	public RefreshToken findByToken(String token) {
		return refreshTokenRepository.findByToken(token)
				.orElseThrow(() -> new TokenRefreshException(token, "Refresh token não encontrado no banco de dados."));
	}
	
	/**
	 * Cria um novo Refresh Token.
	 * AppSec: Garante que tokens antigos do usuário sejam removidos (Single Session enforcement opcional)
	 * ou apenas cria um novo para rotação.
	 */
	public RefreshToken createRefreshToken(String email) {
		RefreshToken refreshToken = new RefreshToken();
		
		refreshToken.setUser(userRepository.findByEmail(email).get());
		refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
		refreshToken.setToken(UUID.randomUUID().toString());
		
		return refreshTokenRepository.save(refreshToken);
	}
	
	/**
	 * Verifica se o token expirou.
	 */
	public RefreshToken verifyExpiration(RefreshToken token) {
		if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
			refreshTokenRepository.delete(token);
			throw new TokenRefreshException(token.getToken(), "Refresh token expirado. Por favor, faça login novamente.");
		}
		return token;
	}
	
	/**
	 * TOKEN ROTATION: Implementação de Segurança.
	 * Verifica o token antigo, deleta-o e gera um novo imediatamente.
	 * Isso previne reutilização de tokens vazados.
	 */
	@Transactional
	public RefreshToken rotateToken(String requestTokenStr) {
		// 1. Busca o token no banco
		RefreshToken oldToken = findByToken(requestTokenStr);
		
		// 2. Verifica validade
		verifyExpiration(oldToken);
		
		// 3. Captura o usuário dono do token
		var user = oldToken.getUser();
		
		// 4. DELETA o token antigo (Rotação)
		refreshTokenRepository.delete(oldToken);
		
		// 5. Força a escrita imediata para evitar Unique Key Violation na criação do novo token
		refreshTokenRepository.flush();
		
		// 6. Gera um NOVO token para o usuário
		return createRefreshToken(user.getEmail());
	}
	
	@Transactional
	public int deleteByUserId(String email) {
		return refreshTokenRepository.deleteByUser(userRepository.findByEmail(email).get());
	}
}