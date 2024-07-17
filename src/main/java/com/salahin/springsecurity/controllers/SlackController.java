package com.salahin.springsecurity.controllers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.salahin.springsecurity.configuration.SlackJwtTokenUtil;
import com.salahin.springsecurity.service.SlackTokenService;
import io.jsonwebtoken.io.IOException;
import jakarta.servlet.http.HttpSession;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Controller
public class SlackController {

    @Value("${slack.client.id}")
    private String clientId;

    @Value("${slack.client.secret}")
    private String clientSecret;

    @Value("${slack.redirect.uri}")
    private String slackRedirectUri;

    @Value("${slack.ngrok.end.point}")
    private String ngrokEndPoint;

    private final SlackJwtTokenUtil slackJwtTokenUtil;
    private final SlackTokenService slackTokenService;

    private static ThreadLocal<String> threadLocalState = new ThreadLocal<>();

    public SlackController(SlackJwtTokenUtil slackJwtTokenUtil, SlackTokenService slackTokenService) {
        this.slackJwtTokenUtil = slackJwtTokenUtil;
        this.slackTokenService = slackTokenService;
    }

    @GetMapping("/slack/login")
    public String slackLogin(HttpSession session) {
        String redirectUri = ngrokEndPoint + slackRedirectUri;
        String state = generateRandomString();
        String nonce = generateRandomString();

        threadLocalState.set(state);

        session.setAttribute("oauth_state", state);
        session.setAttribute("oauth_nonce", nonce);
        String authorizationUrl = UriComponentsBuilder.fromHttpUrl("https://slack.com/openid/connect/authorize")
                .queryParam("client_id", clientId)
                .queryParam("scope", "openid email profile")
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", redirectUri)
                .queryParam("state", state)
                .queryParam("nonce", nonce)
                .build()
                .toUriString();

        return "redirect:" + authorizationUrl;
    }

    @GetMapping("/slack/oauth/callback")
    public String slackCallback(@RequestParam("code") String code, @RequestParam("state") String state, HttpSession session) {
        String redirectUri = ngrokEndPoint + slackRedirectUri;
        String tokenUrl = "https://slack.com/api/openid.connect.token";

        // TODO check the threadLocalState value with method parameter state value

        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl(tokenUrl)
                .queryParam("client_id", clientId)
                .queryParam("client_secret", clientSecret)
                .queryParam("code", code)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("grant_type", "authorization_code");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<?> entity = new HttpEntity<>(headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.postForEntity(uriBuilder.toUriString(), entity, String.class);

        String accessToken = extractAccessTokenFromResponse(response.getBody());
        String idToken = extractIdTokenFromResponse(response.getBody());
        Map<String, Object> claims = new HashMap<>();
        claims = slackJwtTokenUtil.getAllClaimsAsMap(idToken);



        session.setAttribute("access_token", accessToken);

        if (slackJwtTokenUtil.isTokenExpired(idToken)) {
            String refreshToken = extractRefreshTokenFromResponse(response.getBody());
            String newAccessToken = slackTokenService.renewToken(refreshToken);
            session.setAttribute("access_token", newAccessToken);
        }

        return "redirect:https://www.heytaco.chat/";
    }

    private String generateRandomString() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[24];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().encodeToString(randomBytes);
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

    @SneakyThrows
    private String extractIdTokenFromResponse(String responseBody) {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            JsonNode rootNode = objectMapper.readTree(responseBody);
            return rootNode.path("id_token").asText();
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to parse ID token from response");
        }
    }

    @SneakyThrows
    private String extractRefreshTokenFromResponse(String responseBody) {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            JsonNode rootNode = objectMapper.readTree(responseBody);
            return rootNode.path("refresh_token").asText();
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to parse refresh token from response");
        }
    }
}
