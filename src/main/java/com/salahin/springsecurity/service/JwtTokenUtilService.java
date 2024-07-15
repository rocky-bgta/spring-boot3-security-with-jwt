package com.salahin.springsecurity.service;

import com.salahin.springsecurity.entity.JwtTokenInfoEntity;
import com.salahin.springsecurity.model.AuthResponse;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


@Service
public class JwtTokenUtilService {

    @Value("${jwt.secret}")
    private String SECRET;

    private final long jwtAccessExpirationInMs = 1000 * 60 * 60; // 60 minutes
    //private final long jwtAccessExpirationInMs = 80;

    private final long jwtRefreshExpirationInMs = 1000 * 60 * 60 * 24 * 7; // 7 days
    //private final long jwtRefreshExpirationInMs = 80; // 7 days

    //@Value("${jwt.expirationDateInMs}")
    //private int jwtExpirationInMs;

    //@Value("${jwt.refreshExpirationDateInMs}")
    //private int refreshExpirationDateInMs;

    @Autowired
    JwtTokenInfoService jwtTokenInfoService;

    // generate token for user
    public AuthResponse getAccessToken(String username) {
        String tokenType = "Bearer";
        JwtTokenInfoEntity jwtTokenInfoEntity;
        jwtTokenInfoEntity = jwtTokenInfoService.getJwtTokenInfoEntityByUsername(username);
        if (jwtTokenInfoEntity == null) {
            Map<String, Object> claims = new HashMap<>();
            String accessToken = doGenerateToken(claims, username);
            long accessTokenTime = convertMillisecondsToMinutes(jwtAccessExpirationInMs);
            //long refreshTokenTime = jwtRefreshExpirationInMs;

            String refreshToken = doGenerateRefreshToken(claims, username);

            jwtTokenInfoService.saveTokenInfo(username, accessToken, jwtAccessExpirationInMs, refreshToken, jwtRefreshExpirationInMs, tokenType);

            return AuthResponse.builder()
                    .access_token(accessToken)
                    .token_type(tokenType)
                    .expires_in(accessTokenTime + "M")
                    .build();

        } else {
            long accessTokenTime = convertMillisecondsToMinutes(jwtTokenInfoEntity.getAccessTokenExpIn());
            return AuthResponse.builder()
                    .access_token(jwtTokenInfoEntity.getAccessToken())
                    .token_type(tokenType)
                    .expires_in(accessTokenTime+"M")
                    .build();
        }

    }

    public String getRefreshAccessToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        String refreshedAccessToken = doGenerateToken(claims, username);
        return refreshedAccessToken;
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtAccessExpirationInMs))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    public String doGenerateRefreshToken(Map<String, Object> claims, String subject) {

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtRefreshExpirationInMs))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();

    }

  /*  private Claims getAllClaimsFromExpiredToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }*/

    public Map<String, Object> getAllTokenClaims(String token) {
        try {
            Claims claims = getAllClaimsFromToken(token);
            return new HashMap<>(claims);
        } catch (ExpiredJwtException ex) {
            return new HashMap<>(ex.getClaims());
        }
    }

    public Claims convertMapToClaims(Map<String, Object> claimsMap) {
        Claims claims = new DefaultClaims();
        claims.putAll(claimsMap);
        return claims;
    }

    public boolean isTokenExpiredFromClaimsMap(Map<String, Object> claimsMap) {
        Object expObject = claimsMap.get("exp");
        long exp = 0;

        if (expObject instanceof Integer) {
            exp = ((Integer) expObject).longValue();
        } else if (expObject instanceof Long) {
            exp = (Long) expObject;
        }

        Date expiration = new Date(exp * 1000); // JWT stores the exp in seconds, so convert to milliseconds
        return expiration.before(new Date());
    }

    public boolean validateToken(String authToken, UserDetails userDetails) {
        try {
            final String username = getUsernameFromToken(authToken);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(authToken));
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
            throw new BadCredentialsException("INVALID_CREDENTIALS", ex);
        } catch (ExpiredJwtException ex) {
            throw ex;
        }
    }

    //retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    //retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    //check if the token has expired
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    //for retrieving any information from token we will need the secret key
    // Retrieve all claims from token
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Convert milliseconds to minutes
    public static long convertMillisecondsToMinutes(long milliseconds) {
        return milliseconds / (1000 * 60);
    }
}
