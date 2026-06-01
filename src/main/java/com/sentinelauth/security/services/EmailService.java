package com.sentinelauth.security.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

/**
 * EmailService - Envio de Códigos MFA via SMTP Real do Mailtrap.
 * * AppSec Strategy: Envio de credenciais dinâmicas fora de banda (Out-of-band).
 */
@Service
public class EmailService {
	
	private static final Logger logger = LoggerFactory.getLogger(EmailService.class);
	
	private final JavaMailSender mailSender;
	
	public EmailService(JavaMailSender mailSender) {
		this.mailSender = mailSender;
	}
	
	/**
	 * Dispara o e-mail contendo o código OTP para o usuário de forma assíncrona.
	 */
	public void sendMfaCode(String to, String code) {
		try {
			SimpleMailMessage message = new SimpleMailMessage();
			message.setFrom("security@sentinelauth.dev");
			message.setTo(to);
			message.setSubject("🛡️ SentinelAuth - Seu Código de Verificação");
			
			// Mensagem limpa e em conformidade com boas práticas de segurança
			message.setText("Olá!\n\n" +
					"Você solicitou acesso ao SentinelAuth.\n" +
					"Seu código de autenticação de segundo fator (MFA) é:\n\n" +
					"👉 " + code + "\n\n" +
					"Este código é válido por 5 minutos e só pode ser usado uma única vez.\n" +
					"Se você não solicitou este código, por favor altere sua senha imediatamente.\n\n" +
					"Atenciosamente,\n" +
					"Equipe de Segurança SentinelAuth");
			
			mailSender.send(message);
			logger.info("[AppSec-MFA] E-mail enviado com sucesso para o Mailtrap: {}", to);
			
		} catch (Exception e) {
			logger.error("[AppSec-Critical] Falha ao disparar e-mail de segurança: {}", e.getMessage());
		}
	}
}
