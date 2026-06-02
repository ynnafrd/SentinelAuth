package com.sentinelauth.security.events;

import org.springframework.context.ApplicationEvent;

public class SentinelAuditEvent extends ApplicationEvent {
	
	private final String eventType;
	private final String affectedUser;
	private final String ipAddress;
	private final String details;
	
	public SentinelAuditEvent(Object source, String eventType, String affectedUser, String ipAddress, String details) {
		super(source);
		this.eventType = eventType;
		this.affectedUser = affectedUser;
		this.ipAddress = ipAddress;
		this.details = details;
	}
	
	// Apenas Getters para garantir que os dados não sejam alterados após o disparo
	public String getEventType() { return eventType; }
	public String getAffectedUser() { return affectedUser; }
	public String getIpAddress() { return ipAddress; }
	public String getDetails() { return details; }
	

}
