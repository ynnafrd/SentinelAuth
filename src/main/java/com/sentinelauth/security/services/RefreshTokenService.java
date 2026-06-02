package com.sentinelauth.security.services;

import com.sentinelauth.security.exceptions.TokenRefreshException;
import com.sentinelauth.security.model.RefreshToken;
import com.sentinelauth.security.repository.RefreshTokenRepository;
import com.sentinelauth.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.sentinelauth.security.services.AuditPublisher;

import java.time.Instant;
import java.util.UUID;

/**
 * RefreshTokenService - Rotação de Tokens de Segurança (RTR)
 * Implementação robusta contra ataques de reutilização e falhas de rollback transacional.
 */
@Service
public class RefreshTokenService {

    @Value("${jwt.refreshExpiration}")
    private Long refreshTokenDurationMs;

    private final AuditPublisher auditPublisher; // Para publicar eventos de auditoria
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UserRepository userRepository, AuditPublisher auditPublisher) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.auditPublisher = auditPublisher;
    }

    public RefreshToken findByToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new TokenRefreshException(token, "Refresh token não encontrado."));
    }

    public RefreshToken createRefreshToken(String email) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(userRepository.findByEmail(email).get());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setUsed(false);
        refreshToken.setRevoked(false);

        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * TOKEN ROTATION (RTR) com Detecção de Abuso persistente.
     */
    @Transactional(noRollbackFor = SecurityException.class) // Garante que a revogação seja salva mesmo se lançar erro!
    public RefreshToken rotateToken(String requestTokenStr) {
        RefreshToken oldToken = findByToken(requestTokenStr);
        
        // 1. Detecção de Reutilização (Breach Detection)
        if (oldToken.isUsed() || oldToken.isRevoked()) {
            // Se o token já foi usado, assumimos comprometimento de sessão.
            // Revogamos todas as sessões ativas do usuário imediatamente!
            auditPublisher.publish("TOKEN_REUSED", oldToken.getUser().getEmail(), "Tentativa de reutilização de Refresh Token detectada.");
            refreshTokenRepository.revokeAllUserTokens(oldToken.getUser());
            throw new SecurityException("Alerta de Segurança: Tentativa de reutilização de Refresh Token detectada. Todas as sessões do usuário foram invalidadas!");
        }

        // 2. Verifica se o token expirou
        if (oldToken.getExpiryDate().isBefore(Instant.now())) {
            oldToken.setRevoked(true);
            refreshTokenRepository.save(oldToken);
            throw new TokenRefreshException(oldToken.getToken(), "Refresh token expirado.");
        }

        // 3. Marca o token antigo como usado de forma definitiva
        oldToken.setUsed(true);
        refreshTokenRepository.saveAndFlush(oldToken); // Força a gravação imediata no banco

        // 4. Retorna um novo token ativo
        return createRefreshToken(oldToken.getUser().getEmail());
    }
}