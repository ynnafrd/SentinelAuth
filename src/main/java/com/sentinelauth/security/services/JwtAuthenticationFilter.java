package com.sentinelauth.security.services;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.sentinelauth.security.events.SentinelAuditEvent;

import java.io.IOException;
import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * JwtAuthenticationFilter - Filtro com extração por Whitelist (Apenas caracteres JWT).
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
	
	// Regex estrita: Captura apenas caracteres válidos de Base64URL e os dois pontos separadores.
	private static final Pattern JWT_STRICT_PATTERN = Pattern.compile("([A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+)");
	
	private final JwtService jwtService;
	private final UserDetailsService userDetailsService;
	private final AuditPublisher auditPublisher;
	
	@Autowired
	public JwtAuthenticationFilter(JwtService jwtService, @Lazy UserDetailsService userDetailsService, AuditPublisher auditPublisher) {
		this.jwtService = jwtService;
		this.userDetailsService = userDetailsService;
		this.auditPublisher = auditPublisher;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		final String authHeader = request.getHeader("Authorization");
		final String jwt;
		final String userEmail;
		
		// Se não houver cabeçalho ou se não começar com Bearer, segue o fluxo normalmente
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}
		
		try {
			jwt = authHeader.substring(7);
			
			// AppSec Check: Se o token for a string literal do Postman, ignora de forma limpa
			if (jwt.equals("{{sentinel_jwt}}") || jwt.trim().isEmpty()) {
				logger.warn("[AppSec-Filtro] Token inválido ou não resolvido enviado pelo cliente.");
				filterChain.doFilter(request, response);
				return;
			}
			
			userEmail = jwtService.extractUsername(jwt);
			
			if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
				try {
					UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
					
					if (jwtService.isTokenValid(jwt) && userEmail.equals(userDetails.getUsername())) {
						UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
								userDetails, null, userDetails.getAuthorities()
						);
						authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
						SecurityContextHolder.getContext().setAuthentication(authToken);
						logger.info("[AppSec-Filtro] Utilizador {} autenticado com sucesso no contexto.", userEmail);
					} else {
						logger.warn("[AppSec-Filtro] Token inválido ou e-mail divergente para o utilizador: {}", userEmail);
					}
				} catch (UsernameNotFoundException unfe) {
					logger.error("[AppSec-Filtro] O utilizador '{}' extraído do JWT não existe no UserDetailsService atual. " +
							"Verifique se o CustomUserDetailsService está ativo e a ler da base de dados H2.", userEmail);
				}
			}
		} catch (Exception e) {
			// Captura falhas estruturais de parse de JWT malformado, evitando quebras inesperadas
			auditPublisher.publish("INVALID_TOKEN_ATTEMPT", "ANONYMOUS", "Tentativa de acesso com assinatura de token JWT inválida");
			logger.error("[AppSec-Filtro] Erro estrutural ao processar assinatura do token JWT: {}", e.getMessage(), e);
		}
		
		filterChain.doFilter(request, response);
	}
	
	
	private String getCharCodes(String str) {
		return str.chars()
				.mapToObj(String::valueOf)
				.collect(Collectors.joining(", ", "[", "]"));
	}
}