package com.salahin.springsecurity.configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Configuration
public class CsrfConfiguration {

    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = new CookieCsrfTokenRepository();
        repository.setCookieHttpOnly(false); // Allows JavaScript to access the CSRF token
        repository.setCookieName("XSRF-TOKEN");
        return repository;
    }

    @Bean
    public OncePerRequestFilter csrfHeaderFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
                if (csrfToken != null) {
                    response.setHeader("X-CSRF-TOKEN", csrfToken.getToken());
                }
                filterChain.doFilter(request, response);
            }
        };
    }
}
