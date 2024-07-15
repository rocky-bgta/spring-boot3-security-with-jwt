package com.salahin.springsecurity.exception.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
            throws IOException {

        response.setHeader("response-soft-denied-reason", "Authentication Failed");

        // Set the response status to 403 (Forbidden)
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        // Set content type to application/json
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        // Get the current timestamp
        String timestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now());

        // Get the request path
        String path = request.getRequestURI();

        // Get the response status code
        int statusCode = response.getStatus();

        // Prepare the error message
        String jsonResponse = String.format(
                "{\"timestamp\": \"%s\", \"status\": %d, \"denied\": \"%s\", \"message\": \"%s\", \"path\": \"%s\"}",
                timestamp, statusCode, HttpStatus.FORBIDDEN.getReasonPhrase(), accessDeniedException.getMessage(), path
        );

        // Write the response
        response.getWriter().write(jsonResponse);
    }
}
