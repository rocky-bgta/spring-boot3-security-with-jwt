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
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class SlackJwtTokenUtil {

    //private final Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);

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
        String kid = "mB2MAyKSn555isd0EbdhKx6nkyAi9xLq8rvCEb_nOyY";
        PublicKey publicKey = getSigningKey(kid);

        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private String getKidFromToken(String token) {
        return Jwts.parserBuilder()
                .build()
                .parseClaimsJws(token)
                .getHeader()
                .getKeyId();
    }

    public boolean isTokenExpired(String token) {
        try {
            Claims claims = getAllClaimsFromToken(token);
            return claims.getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    /*public boolean validateToken(String token) {
        try {
            getAllClaimsFromToken(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }*/

   /* public boolean validateToken(String token) {
        try {
            getAllClaimsFromToken(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }*/

  /*  public String getUsernameFromToken(String jwtToken) {
        return null;
    }*/

    // Add methods to extract specific claims if needed
}
