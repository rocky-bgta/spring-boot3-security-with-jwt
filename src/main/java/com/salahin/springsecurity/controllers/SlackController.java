package com.salahin.springsecurity.controllers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

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


    @GetMapping("/slack/login")
    public String slackLogin(HttpSession session) {
        String redirectUri = ngrokEndPoint + slackRedirectUri;
        String state = generateRandomString();
        String nonce = generateRandomString();

        // Save state and nonce in session for verification during callback
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

      /*  String authorizationUrl = "https://slack.com/openid/connect/authorize?client_id="
                + clientId +
                "&scope=openid%20email%20profile&response_type=code&redirect_uri="
                + redirectUri + "&state=" + state + "&nonce=" + nonce;
       */
        return "redirect:" + authorizationUrl;
    }

    @GetMapping("/slack/oauth/callback")
    public String slackCallback(@RequestParam("code") String code, @RequestParam("state") String state, HttpSession session, Model model) {
        // Verify state
//        String sessionState = (String) session.getAttribute("oauth_state");
//        if (sessionState == null || !sessionState.equals(state)) {
//            throw new IllegalStateException("Invalid state parameter");
//        }
        String redirectUri = ngrokEndPoint + slackRedirectUri;
        String tokenUrl = "https://slack.com/api/openid.connect.token";

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

        // Assuming the response contains an access token, handle it as needed
        String accessToken = extractAccessTokenFromResponse(response.getBody());
        // Store the access token in the session or wherever appropriate
        session.setAttribute("access_token", accessToken);

        validateTokenAndFetchUser(accessToken);


        model.addAttribute("response", response.getBody());

        return "redirect:https://www.heytaco.chat/";
    }

    private String generateRandomString() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[24];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().encodeToString(randomBytes);
    }

    private String extractAccessTokenFromResponse(String responseBody) {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            JsonNode rootNode = objectMapper.readTree(responseBody);
            JsonNode accessTokenNode = rootNode.path("access_token");
            return accessTokenNode.asText();
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to parse access token from response");
        }
    }

    private void validateTokenAndFetchUser(String accessToken) {
        String url = "https://slack.com/api/openid.connect.userInfo";
        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<String> entity = new HttpEntity<>(headers);

        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);

        // Parse the response to get user details
        // Assuming response contains user information
        // You need to create User class to hold user details

        ObjectMapper objectMapper = new ObjectMapper();




        /*//User user;
        try {
           // user = objectMapper.readValue(response.getBody(), User.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to parse user information from response", e);
        }*/

        // return user;
    }
}
