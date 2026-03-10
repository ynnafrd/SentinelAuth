package com.sentinelauth.security.services;

import com.sentinelauth.security.dto.UserRegistrationDTO;
import com.sentinelauth.security.model.User;
import com.sentinelauth.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {
	
	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
	}
	
	/**
	 * Regista um novo utilizador de forma segura.
	 * @param registrationDTO Dados validados do utilizador
	 * @return O utilizador criado (sem expor a entidade diretamente na controller, idealmente retornaria um DTO de resposta)
	 */
	@Transactional
	public User registerUser(UserRegistrationDTO registrationDTO) {
		// AppSec: Prevenção de Enumeração de Utilizadores (básico)
		// Em um cenário real de alta segurança, o tempo de resposta deste 'if'
		// poderia ser analisado (Timing Attack). Mas funcionalmente, precisamos impedir duplicatas.
		if (userRepository.existsByEmail(registrationDTO.getEmail())) {
			throw new IllegalArgumentException("O e-mail fornecido já está em uso.");
		}
		
		// AppSec: Hashing da senha com Argon2id
		// A senha em texto plano NUNCA sai deste escopo.
		String encodedPassword = passwordEncoder.encode(registrationDTO.getPassword());
		
		// Criação do utilizador com Princípio do Menor Privilégio (apenas ROLE_USER)
		User newUser = new User(
				registrationDTO.getEmail(),
				encodedPassword,
				"ROLE_USER"
		);
		
		return userRepository.save(newUser);
	}
}