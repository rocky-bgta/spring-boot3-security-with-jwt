package com.salahin.springsecurity.service;

import com.salahin.springsecurity.entity.JwtTokenInfoEntity;
import com.salahin.springsecurity.entity.RoleEntity;
import com.salahin.springsecurity.entity.UserEntity;
import com.salahin.springsecurity.model.AuthResponse;
import com.salahin.springsecurity.repository.JwtTokenRepository;
import com.salahin.springsecurity.repository.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.DefaultHeader;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;


import java.security.Key;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@Service
public class JwtTokenUtilService implements InitializingBean {

    @Value("${jwt.secret}")
    private String SECRET;

    // private long JWT_ACCESS_EXPIRATION_IN_MS;// = 1000 * 60 * 60; // 60 minutes
    // private final long jwtAccessExpirationInMs = 80;

    // private long JWT_REFRESH_EXPIRATION_IN_MS;// = 1000 * 60 * 60 * 24 * 7; // 7 days
    // private final long jwtRefreshExpirationInMs = 80; // 7 days

    @Value("${jwt.access.token.expirationTimeInHours}")
    private long JWT_ACCESS_EXPIRATION_IN_MS;

    @Value("${jwt.refresh.token.expirationTimeInDays}")
    private long JWT_REFRESH_EXPIRATION_IN_MS;

    @Override
    public void afterPropertiesSet() {
        // do some initialization work
        JWT_ACCESS_EXPIRATION_IN_MS = TimeUnit.HOURS.toMillis(JWT_ACCESS_EXPIRATION_IN_MS);
        JWT_REFRESH_EXPIRATION_IN_MS = TimeUnit.DAYS.toMillis(JWT_REFRESH_EXPIRATION_IN_MS);
    }

    @Autowired
    JwtTokenInfoService jwtTokenInfoService;

    @Autowired
    JwtTokenRepository jwtTokenRepository;

    @Autowired
    UserRepository userRepository;

   /* @Autowired
    UserService userService;*/

    // generate token for user
    public AuthResponse getAccessToken(String username, Collection<? extends GrantedAuthority> roles) {
        String tokenType = "Bearer";
        JwtTokenInfoEntity jwtTokenInfoEntity;
        jwtTokenInfoEntity = jwtTokenInfoService.getJwtTokenInfoEntityByUsername(username);

        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roles);

        String accessToken = doGenerateToken(claims, username);
        String refreshToken = doGenerateRefreshToken(claims, username);
        // long accessTokenTime;
        if (jwtTokenInfoEntity == null) {

            jwtTokenInfoEntity = jwtTokenInfoService.saveTokenInfo(
                    username,
                    accessToken,
                    JWT_ACCESS_EXPIRATION_IN_MS,
                    refreshToken,
                    JWT_REFRESH_EXPIRATION_IN_MS,
                    tokenType);

            // accessTokenTime = getRemainingTimeInMillisecond(jwtTokenInfoEntity.getTokenIssueTime());

            return getAuthResponseObject(accessToken, tokenType, jwtTokenInfoEntity.getAccessTokenExpIn());

        } else {
            // update access and refreshed token
             long accessTokenTime = getRemainingTimeInMillisecond(jwtTokenInfoEntity.getTokenIssueTime());
            // accessTokenTime = getRemainingTimeInMillisecond(jwtTokenInfoEntity.getTokenIssueTime());
//            jwtTokenInfoEntity = jwtTokenInfoService.updateAccessAndRefreshedToken(
//                    jwtTokenInfoEntity,
//                    accessToken,
//                    JWT_ACCESS_EXPIRATION_IN_MS,
//                    refreshToken,
//                    JWT_REFRESH_EXPIRATION_IN_MS);

            return getAuthResponseObject(
                    jwtTokenInfoEntity.getAccessToken(), tokenType, accessTokenTime);
        }
    }

    private static AuthResponse getAuthResponseObject(String accessToken, String tokenType, long accessTokenTime) {
        return AuthResponse.builder()
                .access_token(accessToken)
                .token_type(tokenType)
                // .expires_in(accessTokenTime + "M")
                .expires_in(accessTokenTime)
                .build();
    }

    public String getRefreshAccessToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        String refreshedAccessToken = doGenerateToken(claims, username);
        return refreshedAccessToken;
    }

    public AuthResponse validateTokenAndGetAllRoles(String token) {
        String tokenType = "Bearer";
        String username;
        // String jwtAccessToken = null;
        Boolean isAccessTokenExpired;
        Boolean isRefreshTokenExpired;
        List<String> rolesFromClaims;
        List<String> roleFromDB;
        UserEntity userEntity;
        Header header = new DefaultHeader();

        try {

            JwtTokenInfoEntity jwtTokenInfoEntity = jwtTokenRepository.findByAccessToken(token);

            if (jwtTokenInfoEntity == null) {
                throw new ExpiredJwtException(header, null, "Given token not valid");
            }

            token = jwtTokenInfoEntity.getAccessToken();
            Map<String, Object> claimsMap = getAllTokenClaims(token);
            isAccessTokenExpired = isTokenExpiredFromClaimsMap(claimsMap);

            // TODO NEED CHANGE WITH USER_ID
            username = claimsMap.get("sub").toString();
            Claims claims = convertMapToClaims(claimsMap);

            // if access still valid
            if (!isAccessTokenExpired) {

                if (!jwtTokenInfoEntity.isStatus()) {
                    throw new ExpiredJwtException(header, claims, "Given token not active");
                }

                /* Get roles from db */

                userEntity = userRepository.findByUsername(username);
                List<RoleEntity> roles = userEntity.getRoleList();

                // rolesFromClaims = getRolesFromClaims(claimsMap);
                roleFromDB = roles.stream().map(r -> r.getRoleName()).toList();

                /*  if (!(new HashSet<>(rolesFromClaims).containsAll(roleFromDB) &&
                        new HashSet<>(roleFromDB).containsAll(rolesFromClaims))) {
                    throw new CustomAccessDeniedException("Don't have rights to access this user");
                }*/

                long accessTokenTime;
                accessTokenTime = getRemainingTimeInMillisecond(jwtTokenInfoEntity.getTokenIssueTime());

                return AuthResponse.builder()
                        .access_token(jwtTokenInfoEntity.getAccessToken())
                        .token_type(tokenType)
                        // .expires_in(accessTokenTime + "M")
                        .expires_in(accessTokenTime)
                        .roles(roleFromDB)
                        //.user(userService.findByUsername(username))
                        .build();

            } else {

                String refreshedToken = jwtTokenInfoEntity.getRefreshedToken();

                claimsMap = getAllTokenClaims(refreshedToken);
                isRefreshTokenExpired = isTokenExpiredFromClaimsMap(claimsMap);

                // if refreshed token is not expired
                if (!isRefreshTokenExpired) {

                    String newAccessToken = doGenerateToken(claims, username);

                    Object expObject = getAllTokenClaims(newAccessToken).get("exp");
                    long accessTokenTime = ((Integer) expObject).longValue();

                    // Update DB with new access token
                    jwtTokenInfoEntity =
                            jwtTokenInfoService.updateAccessToken(jwtTokenInfoEntity, newAccessToken, accessTokenTime);

                    // Convert millisecond to Minute
                    // accessTokenTime = getRemainingTimeInMinutes(jwtTokenInfoEntity.getTokenIssueTime());
                    accessTokenTime = getRemainingTimeInMillisecond(jwtTokenInfoEntity.getTokenIssueTime());
                    rolesFromClaims = getRolesFromClaims(claimsMap);

                    return AuthResponse.builder()
                            .access_token(newAccessToken)
                            .token_type(tokenType)
                            // .expires_in(accessTokenTime + "M")
                            //.user(userService.findByUsername(username))
                            .expires_in(accessTokenTime)
                            .roles(rolesFromClaims)
                            .message("refreshed access token")
                            .build();

                } else {
                    // Delete token row if refreshed token expired that is user needed re-login to application.
                    jwtTokenInfoService.deleteAccessToken(username);

                    // Throw ExpiredJwtException

                    claims = convertMapToClaims(claimsMap);
                    throw new ExpiredJwtException(header, claims, "Token has expired");
                }
            }

            // throw new ExpiredJwtException(header, claims, "Given token expired");
        } catch (ExpiredJwtException | IllegalArgumentException ex) {
            throw new ExpiredJwtException(header, null, "Token has expired");
        }
    }

    public String getRenewAccessToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        String renewAccessToken = doGenerateToken(claims, username);
        return renewAccessToken;
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_ACCESS_EXPIRATION_IN_MS))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String doGenerateRefreshToken(Map<String, Object> claims, String subject) {
        // Add roles to the claims map
        // claims.put("roles", roles);
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_REFRESH_EXPIRATION_IN_MS))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public Map<String, Object> getAllTokenClaims(String token) {
        try {
            Claims claims = getAllClaimsFromToken(token);
            return new HashMap<>(claims);
        } catch (ExpiredJwtException ex) {
            return new HashMap<>(ex.getClaims());
        }
    }

    public List<String> getRolesFromClaims(Map<String, Object> claims) {
        List<String> roles = new ArrayList<>();
        // Assuming the roles are stored as a List<Map<String, Object>> in the claims
        Object rolesObj = claims.get("roles");

        try {
            if (rolesObj instanceof List) {
                List<?> rolesList = (List<?>) rolesObj;

                for (Object roleObj : rolesList) {
                    if (roleObj instanceof Map) {
                        Map<?, ?> roleMap = (Map<?, ?>) roleObj;
                        // Assuming the role name is stored under the "role" key
                        String roleName = (String) roleMap.get("authority");
                        roles.add(roleName);
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Error extracting roles from claims", e);
        }

        return roles;
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

    // retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    // retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    // check if the token has expired
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    // for retrieving any information from token we will need the secret key
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

    public long getRemainingTimeInMillisecond(long tokenIssueTimeInMilliseconds) {
        long currentTimeInMillis = System.currentTimeMillis();
        long expirationTimeInMillis = tokenIssueTimeInMilliseconds + JWT_ACCESS_EXPIRATION_IN_MS;

        // Calculate remaining time
        long remainingTimeInMillis = expirationTimeInMillis - currentTimeInMillis;

        return remainingTimeInMillis;
    }
}
