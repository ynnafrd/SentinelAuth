package com.sentinelauth.security.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * EmailService - Responsável pela comunicação externa.
 * * AppSec: Abstração para envio de códigos de segurança.
 */
@Service
public class EmailService {
	
	private static final Logger logger = LoggerFactory.getLogger(EmailService.class);
	
	/**
	 * Simula ou envia o email com o código MFA.
	 * @param to Destinatário
	 * @param code Código de 6 dígitos
	 */
	public void sendMfaCode(String to, String code) {
		// Integração futura com JavaMailSender ou SendGrid/AWS SES
		logger.info("[AppSec-Email] ENVIANDO CÓDIGO MFA PARA: {}", to);
		logger.info("------------------------------------------");
		logger.info("Olá! O seu código de verificação SentinelAuth é: {}", code);
		logger.info("Este código expira em 5 minutos.");
		logger.info("------------------------------------------");
		
		// Nota: Em desenvolvimento, o código aparecerá no console do Spring Boot.
	}
}