package com.sentinelauth.security.repository;

import com.sentinelauth.security.model.RefreshToken;
import com.sentinelauth.security.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
	
	Optional<RefreshToken> findByToken(String token);
	
	// Revoga todos os tokens ativos de um utilizador específico (útil em caso de deteção de fraude)
	@Transactional
	@Modifying
	@Query("UPDATE RefreshToken r SET r.revoked = true WHERE r.user = :user AND r.revoked = false")
	void revokeAllUserTokens(User user);
}