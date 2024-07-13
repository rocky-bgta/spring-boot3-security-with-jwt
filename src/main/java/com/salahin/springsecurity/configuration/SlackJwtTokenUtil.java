package com.salahin.springsecurity.configuration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

@Service
public class SlackJwtTokenUtil {

    private static final String SLACK_JWKS_URL = "https://slack.com/openid/connect/keys";
    private final Map<String, PublicKey> publicKeys = new HashMap<>();

    private PublicKey getSigningKey(String kid) {
        if (publicKeys.containsKey(kid)) {
            return publicKeys.get(kid);
        }

        try {
            RestTemplate restTemplate = new RestTemplate();
            String jwksResponse = restTemplate.getForObject(SLACK_JWKS_URL, String.class);
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jwks = objectMapper.readTree(jwksResponse);
            JsonNode keys = jwks.get("keys");

            for (JsonNode key : keys) {
                if (key.get("kid").asText().equals(kid)) {
                    byte[] nBytes = Base64.getUrlDecoder().decode(key.get("n").asText());
                    byte[] eBytes = Base64.getUrlDecoder().decode(key.get("e").asText());

                    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(new BigInteger(1, nBytes), new BigInteger(1, eBytes));
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey publicKey = keyFactory.generatePublic(keySpec);

                    publicKeys.put(kid, publicKey);
                    return publicKey;
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to retrieve public key", e);
        }

        throw new RuntimeException("Public key not found for kid: " + kid);
    }

    private Claims getAllClaimsFromToken(String token) {
       // String kid = "mB2MAyKSn555isd0EbdhKx6nkyAi9xLq8rvCEb_nOyY";
        String kid = getKidFromToken(token);
        PublicKey publicKey = getSigningKey(kid);

        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

   /* private String getKidFromToken(String token) {
        return Jwts.parserBuilder()
                .build()
                .parseClaimsJws(token)
                .getHeader()
                .getKeyId();


    }*/

    private String getKidFromToken(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Invalid JWT token");
        }
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode header = objectMapper.readTree(headerJson);
            return header.get("kid").asText();
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse JWT header", e);
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            Claims claims = getAllClaimsFromToken(token);
            return claims.getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    public Map<String, Object> getAllClaimsAsMap(String token) {
        Claims claims = getAllClaimsFromToken(token);
        return new HashMap<>(claims);
    }

}
