package com.sentinelauth.security.services;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

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
	
	@Autowired
	public JwtAuthenticationFilter(JwtService jwtService) {
		this.jwtService = jwtService;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
				throws ServletException, IOException {
		
		final String authHeader = request.getHeader("Authorization");
		
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}
		
		try {
			String rawValue = authHeader.substring(7).trim(); // Remove espaços acidentais
			Matcher matcher = JWT_STRICT_PATTERN.matcher(rawValue);
			
			if (matcher.find()) {
				String jwt = matcher.group(1);
				
				String userEmail = null;
				try {
					userEmail = jwtService.extractUsername(jwt);
				} catch (Exception e) {
					logger.warn("[AppSec] Falha ao extrair usuário do token: {}", e.getMessage());
				}
				
				if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
					if (jwtService.isTokenValid(jwt)) {
						UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
							userEmail, null, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
						
						authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
						SecurityContextHolder.getContext().setAuthentication(authToken);
					}
				}
			} else {
				logger.warn("[AppSec] Formato JWT inválido detectado no Header.");
			}
			
		} catch (Exception e) {
			logger.error("[AppSec] Falha no filtro de autenticação: {}", e.getMessage());
			SecurityContextHolder.clearContext();
		}
		
		filterChain.doFilter(request, response);
	}
	
	private String getCharCodes(String str) {
		return str.chars()
				.mapToObj(String::valueOf)
				.collect(Collectors.joining(", ", "[", "]"));
	}
}