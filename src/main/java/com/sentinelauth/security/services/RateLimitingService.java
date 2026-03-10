package com.sentinelauth.security.services;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * RateLimitingService - Defesa de Perímetro com Bucket4j.
 * Implementa o algoritmo Token Bucket para limitar requisições por IP.
 */
@Service
public class RateLimitingService {
	
	private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
	
	public Bucket resolveBucket(String ip) {
		return buckets.computeIfAbsent(ip, this::newBucket);
	}
	
	private Bucket newBucket(String ip) {
		return Bucket.builder()
				.addLimit(Bandwidth.classic(5, Refill.intervally(5, Duration.ofMinutes(1))))
				.build();
	}
	
	public void clearBuckets() {
		buckets.clear();
	}
}