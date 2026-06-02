package com.sentinelauth.security.services;

import com.sentinelauth.security.model.AuditEvent;
import com.sentinelauth.security.repository.AuditEventRepository;
import com.sentinelauth.security.events.SentinelAuditEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.stereotype.Component;

/**
 * AuditEventListener - O "fantasma" que escuta e persiste os eventos em segundo plano.
 * * AppSec Strategy: Processamento assíncrono para latência zero no cliente.
 */
@Component
@EnableAsync // Permite que o Spring processe tarefas em segundo plano nesta classe
public class AuditEventsListener {
	
	private static final Logger logger = LoggerFactory.getLogger(AuditEventsListener.class);
	private final AuditEventRepository auditRepository;
	
	public AuditEventsListener(AuditEventRepository auditRepository) {
		this.auditRepository = auditRepository;
	}
	
	/**
	 * Escuta todos os disparos de SentinelAuditEvent e os grava no banco.
	 * A anotação @Async garante que esse método rode em uma thread separada.
	 */
	@Async
	@EventListener
	public void handleSentinelAuditEvent(SentinelAuditEvent event) {
		try {
			AuditEvent dbRecord = new AuditEvent(
					event.getEventType(),
					event.getAffectedUser(),
					event.getIpAddress(),
					event.getDetails()
			);
			
			auditRepository.save(dbRecord);
			
			logger.info("[AppSec-Auditoria] Evento '{}' salvo com sucesso para o usuário: {}",
					event.getEventType(), event.getAffectedUser());
			
		} catch (Exception e) {
			// Um erro ao salvar auditoria nunca deve derrubar a requisição principal do usuário
			logger.error("[AppSec-Critical] Falha ao persistir registro de auditoria no banco: {}", e.getMessage());
		}
	}
}