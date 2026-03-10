package com.sentinelauth.security.repository;

import com.sentinelauth.security.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
	// Método para buscar usuário por email (usado no login e validação de registro)
	Optional<User> findByEmail(String email);
	
	// Verifica se existe (para evitar duplicatas sem expor exceções do banco)
	boolean existsByEmail(String email);
}
