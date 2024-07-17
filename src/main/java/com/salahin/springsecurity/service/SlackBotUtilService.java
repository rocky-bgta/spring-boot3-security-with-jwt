package com.salahin.springsecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.salahin.springsecurity.model.SlackUserInfoModel;
import io.jsonwebtoken.io.IOException;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.security.SecureRandom;
import java.util.Base64;

@Service
public class SlackBotUtilService {

    @Value("${slack.client.id}")
    private String clientId;

    @Value("${slack.client.secret}")
    private String clientSecret;

    @Value("${slack.redirect.uri}")
    private String slackRedirectUri;

    @Value("${slack.ngrok.end.point}")
    private String ngrokEndPoint;

    private static final String tokenUrl = "https://slack.com/api/openid.connect.token";
    private static final String authorizationUrl = "https://slack.com/openid/connect/authorize";
    private static final String userInfoUrl = "https://slack.com/api/openid.connect.userInfo";
    private static ThreadLocal<String> threadLocalState = new ThreadLocal<>();

    public String getRedirectionUrl(){
        String redirectUri = getRedirectUri();
        String state = generateRandomString();
        String nonce = generateRandomString();

        threadLocalState.set(state);

        String redirectionUrl = UriComponentsBuilder.fromHttpUrl(authorizationUrl)
                .queryParam("client_id", clientId)
                .queryParam("scope", "openid email profile")
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", redirectUri)
                .queryParam("state", state)
                .queryParam("nonce", nonce)
                .build()
                .toUriString();

        return redirectionUrl;
    }

    @SneakyThrows
    public String getAccessTokenByCode(String code){
        String redirectUri = getRedirectUri();
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
        ResponseEntity<String> AccessTokenResponse = restTemplate.postForEntity(uriBuilder.toUriString(), entity, String.class);

        //Bot token
        String accessToken = extractAccessTokenFromResponse(AccessTokenResponse.getBody());

        return accessToken;

    }

    @SneakyThrows
    public SlackUserInfoModel getUserInfoByAccessToken(String accessToken){
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<String> entity = new HttpEntity<>(headers);

        ResponseEntity<String> userInfoResponse = restTemplate.exchange(userInfoUrl, HttpMethod.GET, entity, String.class);
        ObjectMapper objectMapper = new ObjectMapper();
        SlackUserInfoModel userInfo = objectMapper.readValue(userInfoResponse.getBody(), SlackUserInfoModel.class);
        return userInfo;
    }


   /* public static void main(String[] args) {
        String json = "{ \"ok\": true, \"sub\": \"U07AV9NAVUN\", \"https://slack.com/user_id\": \"U07AV9NAVUN\", \"https://slack.com/team_id\": \"T07AMBUF01M\", \"email\": \"rocky.bgta@gmail.com\", \"email_verified\": true, \"date_email_verified\": 1720421598, \"name\": \"Salehin\", \"picture\": \"https://secure.gravatar.com/avatar/5e3420789435377f10cd1d45feb8d688.jpg\", \"given_name\": \"Salehin\", \"family_name\": \"\", \"locale\": \"en-US\", \"https://slack.com/team_name\": \"Response Soft\", \"https://slack.com/team_domain\": \"responsesoft\", \"https://slack.com/user_image_24\": \"https://secure.gravatar.com/avatar/5e3420789435377f10cd1d45feb8d688.jpg\", \"https://slack.com/user_image_32\": \"https://secure.gravatar.com/avatar/5e3420789435377f10cd1d45feb8d688.jpg\", \"https://slack.com/team_image_default\": true }";

        ObjectMapper objectMapper = new ObjectMapper();
        try {
            SlackUserInfo userInfo = objectMapper.readValue(json, SlackUserInfo.class);
            System.out.println(userInfo.getName()); // Access the data
        } catch (Exception e) {
            e.printStackTrace();
        }
    }*/


    public String getRedirectUri(){
        String redirectUri = ngrokEndPoint + slackRedirectUri;
        return redirectUri;
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
