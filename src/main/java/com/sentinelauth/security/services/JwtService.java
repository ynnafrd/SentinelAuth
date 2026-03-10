package com.sentinelauth.security.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * JwtService - Gerenciador de Tokens com Logs de Integridade.
 */
@Service
public class JwtService {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtService.class);
	
	@Value("${jwt.secret}")
	private String secret;
	
	@Value("${jwt.expiration}")
	private long expiration;
	
	private SecretKey getSigningKey() {
		byte[] keyBytes = this.secret == null ? new byte[0] : this.secret.trim().getBytes(StandardCharsets.UTF_8);
		return Keys.hmacShaKeyFor(keyBytes);
	}
	
	public String generateToken(String email) {
		// Gera token centralizado aqui
		String token = Jwts.builder()
				.subject(email)
				.issuedAt(new Date())
				.expiration(new Date(System.currentTimeMillis() + expiration))
				.signWith(getSigningKey(), SignatureAlgorithm.HS256)
				.compact();
		
		return token;
	}
	
	public boolean isTokenValid(String token) {
		if (token == null) {
			logger.warn("[AppSec] isTokenValid recebido null");
			return false;
		}
		
		try {
			extractAllClaims(token);
			return true;
		} catch (SignatureException e) {
			logger.warn("[AppSec] Validação falhou: assinatura inválida");
			return false;
		} catch (ExpiredJwtException e) {
			logger.warn("[AppSec] Validação falhou: token expirado");
			return false;
		} catch (MalformedJwtException e) {
			logger.warn("[AppSec] Validação falhou: token malformado");
			return false;
		} catch (IllegalArgumentException e) {
			logger.warn("[AppSec] Validação falhou: argumento ilegal ao processar token");
			return false;
		} catch (Exception e) {
			logger.error("[AppSec] Validação falhou: erro inesperado ao processar token - {}", e.getMessage());
			return false;
		}
	}
	
	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}
	
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}
	
	private Claims extractAllClaims(String token) {
		return Jwts.parser()
				.setSigningKey(getSigningKey())
				.build()
				.parseClaimsJws(token)
				.getBody();
	}
	
	private String getCharCodes(String str) {
		return str.chars()
				.mapToObj(String::valueOf)
				.collect(Collectors.joining(", ", "[", "]"));
	}
}