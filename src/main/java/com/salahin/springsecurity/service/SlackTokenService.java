package com.salahin.springsecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.io.IOException;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

@Component
public class SlackTokenService {

    @Value("${slack.client.id}")
    private String clientId;

    @Value("${slack.client.secret}")
    private String clientSecret;

    public String renewToken(String refreshToken) {
        String tokenUrl = "https://slack.com/api/openid.connect.token";

        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl(tokenUrl)
                .queryParam("client_id", clientId)
                .queryParam("client_secret", clientSecret)
                .queryParam("refresh_token", refreshToken)
                .queryParam("grant_type", "refresh_token");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<?> entity = new HttpEntity<>(headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.postForEntity(uriBuilder.toUriString(), entity, String.class);

        if (response.getStatusCode() == HttpStatus.OK) {
            return extractAccessTokenFromResponse(response.getBody());
        } else {
            throw new RuntimeException("Failed to renew token");
        }
    }

    @SneakyThrows
    private String extractAccessTokenFromResponse(String responseBody) {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            JsonNode rootNode = objectMapper.readTree(responseBody);
            return rootNode.path("access_token").asText();
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to parse access token from response");
        }
    }
}
