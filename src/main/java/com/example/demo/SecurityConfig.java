package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableMultiFactorAuthentication(authorities = {FactorGrantedAuthority.PASSWORD_AUTHORITY, FactorGrantedAuthority.WEBAUTHN_AUTHORITY})
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) {
        return http
                .formLogin(withDefaults())
                .webAuthn((webAuthn) -> webAuthn
                        .rpName("Spring Security Relying Party")
                        .rpId("localhost")
                        .allowedOrigins("http://localhost:8080"))
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/webauthn/register")
                        .access(AuthenticatedAuthorizationManager.authenticated())
                        .anyRequest()
                        .authenticated())
                .build();
    }

    @Bean
    UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }
}
