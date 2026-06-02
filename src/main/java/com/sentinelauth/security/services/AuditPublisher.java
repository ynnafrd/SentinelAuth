package com.sentinelauth.security.services;

import com.sentinelauth.security.events.SentinelAuditEvent;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * AuditPublisher - Utilitário para disparar eventos de auditoria de forma limpa.
 * * AppSec Design: Auto-resolução de IP de origem via RequestContextHolder.
 */
@Component
public class AuditPublisher {
	
	private final ApplicationEventPublisher eventPublisher;
	
	public AuditPublisher(ApplicationEventPublisher eventPublisher) {
		this.eventPublisher = eventPublisher;
	}
	
	/**
	 * Publica um evento de auditoria no ecossistema do Spring.
	 * O IP do usuário é descoberto automaticamente através do contexto da thread atual.
	 */
	public void publish(String eventType, String affectedUser, String details) {
		String clientIp = resolveClientIp();
		
		SentinelAuditEvent event = new SentinelAuditEvent(
				this,
				eventType,
				affectedUser,
				clientIp,
				details
		);
		
		eventPublisher.publishEvent(event);
	}
	
	/**
	 * Mágica de Infraestrutura: Extrai o IP real do cliente, considerando proxy e load balancers.
	 */
	private String resolveClientIp() {
		ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		if (attributes == null) {
			return "SISTEMA_INTERNO";
		}
		
		HttpServletRequest request = attributes.getRequest();
		String xfHeader = request.getHeader("X-Forwarded-For");
		
		if (xfHeader == null) {
			return request.getRemoteAddr();
		}
		
		return xfHeader.split(",")[0]; // Retorna o primeiro IP caso passe por múltiplos proxies
	}
}