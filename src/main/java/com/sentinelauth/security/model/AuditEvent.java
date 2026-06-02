package com.sentinelauth.security.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "audit_events")
public class AuditEvent {
	
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private UUID id;
	
	// Garante que saberemos o momento exato em UTC
	@Column(nullable = false, updatable = false)
	private LocalDateTime timestamp;
	
	// O tipo do evento (ex: LOGIN_SUCCESS, LOGIN_FAILED, MFA_REJECTED, TOKEN_REUSE)
	@Column(nullable = false, updatable = false)
	private String eventType;
	
	// Quem sofreu ou realizou a ação (e-mail ou username)
	@Column(nullable = false, updatable = false)
	private String affectedUser;
	
	// IP de origem da requisição para rastreamento geográfico ou bloqueios futuros
	@Column(nullable = false, updatable = false)
	private String ipAddress;
	
	// Detalhes adicionais (ex: "Senha incorreta", "Tentativa de reuso do token X")
	@Column(length = 500, updatable = false)
	private String details;
	
	// Construtor padrão exigido pelo JPA
	public AuditEvent() {}
	
	// Construtor auxiliar para facilitar a criação dos eventos no código
	public AuditEvent(String eventType, String affectedUser, String ipAddress, String details) {
		this.timestamp = LocalDateTime.now(); // Pega o horário atual do sistema
		this.eventType = eventType;
		this.affectedUser = affectedUser;
		this.ipAddress = ipAddress;
		this.details = details;
	}
	
	// Getters (Note que não criamos Setters, pois logs de auditoria NUNCA devem ser alterados!)
	public UUID getId() { return id; }
	public LocalDateTime getTimestamp() { return timestamp; }
	public String getEventType() { return eventType; }
	public String getAffectedUser() { return affectedUser; }
	public String getIpAddress() { return ipAddress; }
	public String getDetails() { return details; }
}