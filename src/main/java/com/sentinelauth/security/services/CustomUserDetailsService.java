package com.sentinelauth.security.services;

import com.sentinelauth.security.model.User;
import com.sentinelauth.security.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

/**
 * CustomUserDetailsService - Integração do Spring Security com a Base de Dados.
 * * AppSec Strategy: Autenticação baseada em utilizadores reais gravados em base de dados (H2).
 * Substitui a dependência do InMemoryUserDetailsManager.
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {
	
	private final UserRepository userRepository;
	
	public CustomUserDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}
	
	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		// Procura o utilizador na base de dados real H2 pelo e-mail fornecido
		User user = userRepository.findByEmail(email)
				.orElseThrow(() -> new UsernameNotFoundException("Utilizador não encontrado com o e-mail: " + email));
		
		// Mapeia o utilizador do domínio para a estrutura de UserDetails exigida pelo Spring Security
		return org.springframework.security.core.userdetails.User.builder()
				.username(user.getEmail())
				.password(user.getPasswordHash()) // Password já em Argon2id no banco
				.authorities(user.getRole()) // Associa a role correspondente (ex: ROLE_USER)
				.build();
	}
}