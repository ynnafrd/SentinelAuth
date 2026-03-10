package com.sentinelauth.security.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.FORBIDDEN)
public class TokenRefreshException extends RuntimeException {
	public TokenRefreshException(String token, String message) {
		super(String.format("Falha no Refresh Token [%s]: %s", token, message));
	}
}