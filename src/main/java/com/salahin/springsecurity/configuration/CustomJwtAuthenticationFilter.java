package com.salahin.springsecurity.configuration;

import com.salahin.springsecurity.entity.JwtTokenInfoEntity;
import com.salahin.springsecurity.model.AuthResponse;
import com.salahin.springsecurity.repository.JwtTokenRepository;
import com.salahin.springsecurity.service.JwtTokenService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.DefaultHeader;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class CustomJwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;
    private final CustomUserDetailsService customUserDetailsService;

    @Autowired
    JwtTokenRepository jwtTokenRepository;

    @Autowired
    JwtTokenService jwtTokenService;

    public CustomJwtAuthenticationFilter(JwtTokenUtil jwtTokenUtil, CustomUserDetailsService customUserDetailsService) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.customUserDetailsService = customUserDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        final String requestTokenHeader = request.getHeader("Authorization");
        String username = null;
        String jwtAccessToken = null;
        Boolean isAccessTokenExpired = false;
        Boolean isRefreshTokenExpired = false;

        // JWT Token is in the form "Bearer token". Remove Bearer word and get  only the Token
        try {
            if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {

                jwtAccessToken = requestTokenHeader.substring(7);

                Map<String, Object> claimsMap = jwtTokenUtil.getAllTokenClaims(jwtAccessToken);

                isAccessTokenExpired = jwtTokenUtil.isTokenExpiredFromClaimsMap(claimsMap);

                username = claimsMap.get("sub").toString();

                // username = jwtTokenUtil.getUsernameFromToken(jwtToken);

            } else {
                logger.warn("JWT Token does not begin with Bearer String");
            }

            // if token is valid and not expired
            if (!isAccessTokenExpired && username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                UserDetails userDetails = this.customUserDetailsService.loadUserByUsername(username);
                JwtTokenInfoEntity jwtTokenInfoEntity = jwtTokenRepository.findByUsername(username);

                /* To check requested accessToken exist in DB */
                if (jwtTokenInfoEntity != null && jwtTokenInfoEntity.getAccessToken().equals(jwtAccessToken) && jwtTokenInfoEntity.isStatus()) {


                    // if token is valid configure Spring Security to manually set
                    // authentication
                    if (jwtTokenUtil.validateToken(jwtAccessToken, userDetails)) {

                        setSecurityContext(new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities()), request);
                    }
                }
            }

            // if access token expired that not valid
            if (isAccessTokenExpired) {

                /* retrieved refreshed token for DB */
                JwtTokenInfoEntity jwtTokenInfoEntity = jwtTokenRepository.findByUsername(username);

                String refreshedToken = jwtTokenInfoEntity.getRefreshedToken();

                Map<String, Object> claimsMap = jwtTokenUtil.getAllTokenClaims(refreshedToken);
                isRefreshTokenExpired = jwtTokenUtil.isTokenExpiredFromClaimsMap(claimsMap);


                // if refreshed token is not expired
                if (!isRefreshTokenExpired) {
                    UserDetails userDetails = this.customUserDetailsService.loadUserByUsername(username);
                    String newAccessToken = jwtTokenUtil.getRefreshAccessToken(username);

                    Object expObject = jwtTokenUtil.getAllTokenClaims(newAccessToken).get("exp");
                    long accessTokenTime = ((Integer) expObject).longValue();

                    accessTokenTime = JwtTokenUtil.convertMillisecondsToMinutes(accessTokenTime);
                    jwtTokenService.updateAccessToken(username, newAccessToken, accessTokenTime);
                    setSecurityContext(new UsernamePasswordAuthenticationToken(
                            username, null, userDetails.getAuthorities()), request);
                } else {
                    // Delete token row if refreshed token expired that is user needed re-login to application.
                    jwtTokenService.deleteAccessToken(username);

                    // Throw ExpiredJwtException
                    Header header = new DefaultHeader();
                    Claims claims = jwtTokenUtil.convertMapToClaims(claimsMap);
                    throw new ExpiredJwtException(header, claims, "Token has expired");
                }
            }

        } catch (ExpiredJwtException ex) {
            System.out.println("Unable to get JWT Token");
            request.setAttribute("exception", ex);

        }

        chain.doFilter(request, response);


        //===
   /* } catch (ExpiredJwtException ex) {
        String isRefreshToken = request.getHeader("isRefreshToken");
        String requestURL = request.getRequestURL().toString();
        // allow for Refresh Token creation if following conditions are true.
        if (isRefreshToken != null && isRefreshToken.equals("true") && requestURL.contains("refreshtoken")) {
            allowForRefreshToken(ex, request);
        } else
            request.setAttribute("exception", ex);
    } catch (BadCredentialsException ex) {
        request.setAttribute("exception", ex);

        chain.doFilter(request, response);*/
        //===

    }

    private static void setSecurityContext(UsernamePasswordAuthenticationToken userDetails, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = userDetails;
        usernamePasswordAuthenticationToken
                .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        // After setting the Authentication in the context, we specify
        // that the current user is authenticated. So it passes the
        // Spring Security Configurations successfully.
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }

   /*

   private void allowForRefreshToken(ExpiredJwtException ex, HttpServletRequest request) {

        // create a UsernamePasswordAuthenticationToken with null values.
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                null, null, null);
        // After setting the Authentication in the context, we specify
        // that the current user is authenticated. So it passes the
        // Spring Security Configurations successfully.
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        // Set the claims so that in controller we will be using it to create
        // new JWT
        request.setAttribute("claims", ex.getClaims());

    }

    */

}
