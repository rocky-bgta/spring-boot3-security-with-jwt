package com.salahin.springsecurity.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Collections;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
			throws IOException {

		//String path = request.getRequestURI();
		response.setHeader("response-soft", "Authentication Failed");

		// Set the response status to 401 (Unauthorized)
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

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
				"{\"timestamp\": \"%s\", \"status\": %d, \"error\": \"%s\", \"message\": \"%s\", \"path\": \"%s\"}",
				timestamp, statusCode, HttpStatus.UNAUTHORIZED.getReasonPhrase(), authException.getMessage(), path
		);

		// Write the response
		response.getWriter().write(jsonResponse);
	}

}
