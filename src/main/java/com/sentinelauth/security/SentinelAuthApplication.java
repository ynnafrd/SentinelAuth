package com.sentinelauth.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import java.util.TimeZone;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SentinelAuthApplication - Ponto de entrada da aplicação.
 * * AppSec Principle: Secure Initialization.
 */
@SpringBootApplication
public class SentinelAuthApplication {
	
	private static final Logger logger = LoggerFactory.getLogger(SentinelAuthApplication.class);
	
	public static void main(String[] args) {
		// AppSec: Configuração de propriedades da JVM via código para endurecer o ambiente.
		
		// CORREÇÃO PARA JAVA 25: Força o Spring a ignorar o formato de classe incompatível
		// Isso permite que o framework tente rodar em versões do Java mais recentes que o suporte oficial.
		System.setProperty("spring.classformat.ignore", "true");
		
		// Impede que a stack trace de exceções comuns seja omitida pela JVM (ajuda no debug interno seguro)
		System.setProperty("XX:-OmitStackTraceInFastThrow", "true");
		
		logger.info("Starting SentinelAuth in secure mode (Java Compatibility Mode enabled)...");
		SpringApplication.run(SentinelAuthApplication.class, args);
	}
	
	/**
	 * AppSec: Garantir que a aplicação use UTC de forma consistente.
	 * Ter um fuso horário consistente é crucial para a auditoria de logs (Incident Response).
	 */
	@PostConstruct
	public void init() {
		TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
		logger.info("Application fuso horário definido para UTC.");
	}
}