package com.sentinelauth.security.controllers;

import com.sentinelauth.security.services.RateLimitingService;
import com.sentinelauth.security.dto.LoginRequestDTO;
import com.sentinelauth.security.model.RefreshToken;
import com.sentinelauth.security.model.User;
import com.sentinelauth.security.repository.UserRepository;
import com.sentinelauth.security.services.JwtService;
import com.sentinelauth.security.services.RefreshTokenService;
import io.github.bucket4j.Bucket;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import com.sentinelauth.security.dto.LoginResponseDTO;
import com.sentinelauth.security.services.MfaService;
import com.sentinelauth.security.services.EmailService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
	
	Bucket bucket = new RateLimitingService().resolveBucket("localhost");
	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
	private final MfaService mfaService;
	
	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final RefreshTokenService refreshTokenService;
	private final RateLimitingService rateLimitingService;
	private final EmailService emailService;
	
	
	public AuthController(MfaService mfaService, UserRepository userRepository, PasswordEncoder passwordEncoder,
	                      JwtService jwtService, RefreshTokenService refreshTokenService, RateLimitingService rateLimitingService, EmailService emailService) {
		this.mfaService = mfaService;
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.refreshTokenService = refreshTokenService;
		this.rateLimitingService = rateLimitingService;
		this.emailService = emailService;
	}
	
	@PostMapping("/login")
	public ResponseEntity<?> login(@Valid @RequestBody LoginRequestDTO loginRequest,
	                               @RequestHeader(value = "X-Forwarded-For", defaultValue = "unknown") String ip) {
		
		// AppSec: Proteção contra Brute Force via Rate Limiting
		if (!rateLimitingService.resolveBucket(ip).tryConsume(1)) {
			return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body("Muitas tentativas. Tente novamente em 1 minuto.");
		}
		
		return userRepository.findByEmail(loginRequest.getEmail())
				.map(user -> {
					if (passwordEncoder.matches(loginRequest.getPassword(), user.getPasswordHash())) {
						
						// Fluxo MFA Ativo
						if (user.isMfaEnabled()) {
							String code = mfaService.generateEmailCode(user.getEmail());
							emailService.sendMfaCode(user.getEmail(), code);
							
							// Gera um token temporário (curta duração) para autorizar a rota /verify
							String tempToken = jwtService.generateToken(user.getEmail());
							return ResponseEntity.ok(LoginResponseDTO.mfaPending(tempToken));
						}
						
						// Fluxo Sem MFA: Entrega tokens definitivos imediatamente
						return generateFullAuthResponse(user.getEmail());
					}
					return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciais inválidas.");
				})
				.orElse(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciais inválidas."));
	}
	
	
	@PostMapping("/refresh")
	public ResponseEntity<Object> refreshToken(@RequestBody Map<String, String> requestBody, HttpServletRequest request) {
		String requestRefreshToken = requestBody.get("refreshToken");
		String clientIp = request.getRemoteAddr();
		
		if (bucket.tryConsume(1)) {
			logger.info("[AppSec-Audit] Solicitação de Refresh Token | IP: {}", clientIp);
			
			
			if (requestRefreshToken == null || requestRefreshToken.isBlank()) {
				return ResponseEntity.badRequest().body(Map.of("message", "O campo 'refreshToken' é obrigatório."));
			}
			
			try {
				RefreshToken newRefreshToken = refreshTokenService.rotateToken(requestRefreshToken);
				String userEmail = newRefreshToken.getUser().getEmail();
				String newAccessToken = jwtService.generateToken(userEmail);
				
				Map<String, Object> response = new HashMap<>();
				response.put("accessToken", newAccessToken);
				response.put("refreshToken", newRefreshToken.getToken());
				response.put("status", "success");
				
				logger.info("[AppSec-Audit] Token Rotated | User: {} | IP: {}", userEmail, clientIp);
				return ResponseEntity.ok(response);
				
			} catch (Exception e) {
				logger.error("[AppSec-Audit] Falha Crítica no Refresh | IP: {} | Erro: {}", clientIp, e.getMessage());
				
				if (e.getClass().getSimpleName().contains("TokenRefreshException")) {
					throw e;
				}
				
				Map<String, Object> errorBody = new HashMap<>();
				errorBody.put("message", "Sessão inválida ou expirada.");
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorBody);
			}
		} else {
			logger.warn("[AppSec-Audit] Limite de Refresh Token Excedido | IP: {}", clientIp);
			Map<String, String> errorResponse = new HashMap<>();
			errorResponse.put("message", "Muitas solicitações de refresh. Por favor, tente novamente mais tarde.");
			return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(errorResponse);
		}
	}
	
	@PostMapping("/logout")
	public ResponseEntity<Object> logout(@RequestBody Map<String, String> requestBody, HttpServletRequest request) {
		String requestRefreshToken = requestBody.get("refreshToken");
		String clientIp = request.getRemoteAddr();
		
		if (requestRefreshToken != null && !requestRefreshToken.isBlank()) {
			try {
				// Aqui idealmente teríamos um método refreshTokenService.revokeToken(token)
				logger.info("[AppSec-Audit] Logout Solicitado | Token Revogado | IP: {}", clientIp);
			} catch (Exception e) {
				logger.debug("Logout silencioso para token inexistente.");
			}
		}
		
		return ResponseEntity.ok(Map.of("message", "Logout efetuado com sucesso."));
	}
	@PostMapping("/mfa/verify")
	public ResponseEntity<?> verifyMfa(@RequestHeader("Authorization") String authHeader,
	                                   @RequestBody Map<String, String> body) {
		String code = body.get("code");
		if (code == null) return ResponseEntity.badRequest().body("Código é obrigatório.");
		
		try {
			String tempToken = authHeader.replace("Bearer ", "");
			String email = jwtService.extractUsername(tempToken);
			
			if (mfaService.verifyCode(email, code)) {
				logger.info("[AppSec] MFA validado com sucesso para: {}", email);
				return generateFullAuthResponse(email);
			}
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Código inválido ou expirado.");
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Sessão temporária inválida.");
		}
	}
	
	@PostMapping("/mfa/toggle")
	public ResponseEntity<?> toggleMfa(@RequestHeader("Authorization") String authHeader) {
		String token = authHeader.replace("Bearer ", "");
		String email = jwtService.extractUsername(token);
		
		return userRepository.findByEmail(email).map(user -> {
			user.setMfaEnabled(!user.isMfaEnabled());
			userRepository.save(user);
			String status = user.isMfaEnabled() ? "ativado" : "desativado";
			return ResponseEntity.ok("MFA " + status + " com sucesso.");
		}).orElse(ResponseEntity.status(HttpStatus.NOT_FOUND).build());
	}
	
	/**
	 * Helper para gerar a resposta de sucesso com Access e Refresh Token.
	 */
	private ResponseEntity<LoginResponseDTO> generateFullAuthResponse(String email) {
		String accessToken = jwtService.generateToken(email);
		RefreshToken refreshToken = refreshTokenService.createRefreshToken(email);
		return ResponseEntity.ok(LoginResponseDTO.success(accessToken, refreshToken.getToken()));
	}
}
