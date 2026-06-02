package com.sentinelauth.security.controllers;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import com.sentinelauth.security.services.JwtAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    /**
     * CADEIA 1: Isolada exclusivamente para o H2 Console.
     * A anotação @Order(1) garante que o Spring Security teste esta regra primeiro.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain h2ConsoleSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // Aplica esta cadeia APENAS para rotas que comecem com /h2-console/
                .securityMatcher(new AntPathRequestMatcher("/h2-console/**"))
                
                // Libera o acesso total para os frames do H2
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                
                // Desativa as proteções que quebram o layout do H2
                .csrf(csrf -> csrf.disable())
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()));
        
        // NOTA: Não adicionamos o JwtAuthenticationFilter aqui! O H2 fica totalmente isolado dele.
        return http.build();
    }
    
    /**
     * CADEIA 2: A segurança principal da sua API (SentinelAuth).
     * Processada logo em seguida para todas as outras rotas do sistema.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http
                // Desativamos CSRF para a API pois utilizamos autenticação Stateless (JWT)
                .csrf(csrf -> csrf.disable())
                
                .authorizeHttpRequests(auth -> auth
                        // Rotas Públicas da sua API
                        .requestMatchers(new AntPathRequestMatcher("/api/users/register")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/api/auth/login")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/api/auth/mfa/verify")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/error")).permitAll()
                        
                        // Qualquer outra rota exige autenticação JWT
                        .anyRequest().authenticated()
                );
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        // Retorna a implementação padrão do Argon2id recomendada pelo Spring Security
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }
}