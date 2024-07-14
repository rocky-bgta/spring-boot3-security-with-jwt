package com.salahin.springsecurity.configuration;

import com.salahin.springsecurity.entity.JwtTokenInfoEntity;
import com.salahin.springsecurity.entity.UserEntity;
import com.salahin.springsecurity.model.AuthResponse;
import com.salahin.springsecurity.repository.JwtTokenRepository;
import com.salahin.springsecurity.repository.UserRepository;
import com.salahin.springsecurity.service.JwtTokenService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Example;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


@Service
public class JwtTokenUtil {

    @Value("${jwt.secret}")
    private String SECRET;

    //public static final String SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";

    private final long jwtAccessExpirationInMs = 1000 * 60 * 15; // 15 minutes
    //private final long jwtRefreshExpirationInMs = 1000 * 60 * 60 * 24 * 7; // 7 days

    //@Value("${jwt.expirationDateInMs}")
    //private int jwtExpirationInMs;

    @Value("${jwt.refreshExpirationDateInMs}")
    private int refreshExpirationDateInMs;

    @Autowired
    JwtTokenService jwtTokenService;

    // generate token for user
    public AuthResponse getAccessToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        String accessToken = doGenerateToken(claims, userDetails.getUsername());
        long minutes = convertMillisecondsToMinutes(jwtAccessExpirationInMs);
        AuthResponse authResponse = AuthResponse.builder()
                .access_token(accessToken)
                .token_type("Bearer")
                .expires_in(minutes+"M")
                .build();


        jwtTokenService.saveTokenInfo(userDetails.getUsername(),accessToken);

        return authResponse;
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtAccessExpirationInMs))
                // .signWith(SignatureAlgorithm.HS512, secret).compact();
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    public String doGenerateRefreshToken(Map<String, Object> claims, String subject) {

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + refreshExpirationDateInMs))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();

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
