package com.sentinelauth.security.controllers;

import com.sentinelauth.security.services.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * Configuração Central de Segurança (SentinelAuth)
 * Atualizada com Hardening de Cabeçalhos (CSP, HSTS, Referrer Policy).
 * Foco: AppSec Perímetro e Proteção de Navegador.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Autowired
    private JwtAuthenticationFilter jwtFilter;
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        // AppSec: Argon2id - Recomendação OWASP para hashing de senhas.
        return new Argon2PasswordEncoder(16, 32, 1, 65536, 3);
    }
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Desativado para APIs baseadas em JWT (Stateless)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                
                // --- HARDENING DE CABEÇALHOS (APPSEC PHASE 2) ---
                .headers(headers -> headers
                        // 1. HSTS: Força o uso de HTTPS por 1 ano (31536000 segundos)
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31536000))
                        
                        // 2. CSP: Define políticas contra injeção de scripts (XSS)
                        // Como somos uma API, restringimos ao máximo ('self').
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"))
                        
                        // 3. Referrer Policy: Controla quanta informação de origem é enviada em links
                        .referrerPolicy(referrer -> referrer
                                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                        
                        // 4. Frame Options: Impede que a API seja renderizada dentro de iframes (Anti-Clickjacking)
                        .frameOptions(frame -> frame.deny())
                        
                        // 5. X-Content-Type-Options: Previne Sniffing de MIME-type
                        .contentTypeOptions(org.springframework.security.config.Customizer.withDefaults())
                )
                
                .authorizeHttpRequests(auth -> auth
                        // Whitelist de rotas públicas
                        .requestMatchers("/api/users/register").permitAll()
                        .requestMatchers("/api/auth/login").permitAll()
                        .requestMatchers("/api/auth/refresh").permitAll()
                        .requestMatchers("/h2-console/**").permitAll() // Apenas para ambiente de desenvolvimento
                        
                        // Rotas protegidas (Exigem JWT)
                        .anyRequest().authenticated()
                );
        
        // Adiciona o filtro JWT antes do filtro de autenticação padrão do Spring
        http.addFilterBefore(jwtFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
}