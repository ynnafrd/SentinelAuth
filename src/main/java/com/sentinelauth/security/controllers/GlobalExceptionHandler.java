package com.sentinelauth.security.controllers;

import com.sentinelauth.security.exceptions.TokenRefreshException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@ControllerAdvice
public class GlobalExceptionHandler {
	
	@ExceptionHandler(TokenRefreshException.class)
	public ResponseEntity<Object> handleTokenRefreshException(TokenRefreshException ex) {
		Map<String, Object> body = new HashMap<>();
		body.put("message", ex.getMessage());
		body.put("status", HttpStatus.FORBIDDEN.value());
		return new ResponseEntity<>(body, HttpStatus.FORBIDDEN);
	}
	
	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Object> handleValidationExceptions(MethodArgumentNotValidException ex) {
		Map<String, Object> body = new HashMap<>();
		String errors = ex.getBindingResult()
				.getFieldErrors()
				.stream()
				.map(error -> error.getField() + ": " + error.getDefaultMessage())
				.collect(Collectors.joining(", "));
		
		body.put("message", "Validation failed: " + errors);
		body.put("status", HttpStatus.BAD_REQUEST.value());
		return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
	}
	
	@ExceptionHandler(Exception.class)
	public ResponseEntity<Object> handleGeneralException(Exception ex) {
		Map<String, Object> body = new HashMap<>();
		// AppSec: Não vazar stack trace em produção
		body.put("message", "An internal server error occurred.");
		body.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
		return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
	}
}