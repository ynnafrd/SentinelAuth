package com.sentinelauth.security.repository;

import com.sentinelauth.security.model.AuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {
	// Por enquanto o JpaRepository já fornece os métodos básicos para salvar e consultar eventos de auditoria.
	// Podemos adicionar consultas personalizadas aqui no futuro, se necessário.
}
