package com.sentinelauth.security.controllers;

import com.sentinelauth.security.dto.UserResponseDTO;
import com.sentinelauth.security.model.User;
import com.sentinelauth.security.repository.UserRepository;
import com.sentinelauth.security.services.UserService;
import com.sentinelauth.security.dto.UserRegistrationDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.stream.Collectors;

/**
 * UserController - Gestão de Utilizadores.
 * * AppSec Principle: Observability & Defense in Depth.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {
	
	private static final Logger logger = LoggerFactory.getLogger(UserController.class);
	
	private final UserService userService;
	private final UserRepository userRepository;
	
	public UserController(UserService userService, UserRepository userRepository) {
		this.userService = userService;
		this.userRepository = userRepository;
	}
	
	@PostMapping("/register")
	public ResponseEntity<UserResponseDTO> register(@Valid @RequestBody UserRegistrationDTO registrationDTO) {
		logger.info("[AppSec] Tentativa de registro: {}", registrationDTO.getEmail());
		User user = userService.registerUser(registrationDTO);
		UserResponseDTO response = new UserResponseDTO(user.getId(), user.getEmail(), user.getRole());
		return ResponseEntity.status(HttpStatus.CREATED).body(response);
	}
	
	/**
	 * Retorna o perfil do utilizador autenticado.
	 * Adicionado logs de depuração de segurança.
	 */
	@GetMapping("/me")
	public ResponseEntity<Object> getCurrentUser(Authentication authentication, HttpServletRequest request) {
		
		if (authentication == null) {
			logger.error("[AppSec] Objeto de autenticação é NULL no Controller. O Filtro falhou em injetar o contexto.");
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Erro de Autenticação: Contexto vazio.");
		}
		
		logger.info("[AppSec] Usuário autenticado detectado: {}", authentication.getName());
		logger.info("[AppSec] Permissões (Roles) detectadas: {}",
				authentication.getAuthorities().stream()
						.map(GrantedAuthority::getAuthority)
						.collect(Collectors.joining(", ")));
		
		String email = authentication.getName(); // getName() no Spring Security geralmente retorna o principal (email)
		
		return userRepository.findByEmail(email)
				.map(user -> {
					UserResponseDTO response = new UserResponseDTO(user.getId(), user.getEmail(), user.getRole());
					return ResponseEntity.ok((Object) response);
				})
				.orElseGet(() -> {
					logger.warn("[AppSec] Token válido para {}, mas usuário não existe no H2 (Restart detectado?).", email);
					return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Utilizador não encontrado no banco de dados.");
				});
	}
}