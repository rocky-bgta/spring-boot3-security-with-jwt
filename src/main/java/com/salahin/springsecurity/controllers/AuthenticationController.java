package com.salahin.springsecurity.controllers;

import com.salahin.springsecurity.configuration.CustomAuthenticationManager;
import com.salahin.springsecurity.configuration.CustomUserDetailsService;
import com.salahin.springsecurity.configuration.JwtTokenUtil;
import com.salahin.springsecurity.model.AuthRequest;
import com.salahin.springsecurity.model.AuthResponse;
import io.jsonwebtoken.impl.DefaultClaims;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;


@RestController
public class AuthenticationController {

    private final CustomUserDetailsService userDetailsService;
    private final JwtTokenUtil jwtTokenUtil;
    private final CustomAuthenticationManager customAuthenticationManager;

    public AuthenticationController(
            CustomUserDetailsService userDetailsService,
            JwtTokenUtil jwtTokenUtil,
            CustomAuthenticationManager customAuthenticationManager) {

        this.userDetailsService = userDetailsService;
        this.jwtTokenUtil = jwtTokenUtil;
        this.customAuthenticationManager = customAuthenticationManager;
    }

    @PostMapping(value = "/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthRequest authRequest) throws Exception {
        customAuthenticationManager.authenticate
                (
                        new UsernamePasswordAuthenticationToken
                                (
                                        authRequest.getUsername(),
                                        authRequest.getPassword()
                                )
                );

        final UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getUsername());
        AuthResponse authResponse = jwtTokenUtil.getAccessToken(userDetails);
        return ResponseEntity.ok(authResponse);
    }

    @RequestMapping(value = "/refreshtoken", method = RequestMethod.GET)
    public ResponseEntity<?> refreshtoken(HttpServletRequest request) throws Exception {
        // From the HttpRequest get the claims
        DefaultClaims claims = (io.jsonwebtoken.impl.DefaultClaims) request.getAttribute("claims");

        Map<String, Object> expectedMap = getMapFromIoJsonwebtokenClaims(claims);
        String token = jwtTokenUtil.doGenerateRefreshToken(expectedMap, expectedMap.get("sub").toString());
        AuthResponse authResponse = AuthResponse.builder()
                .access_token(token)
                .build();
        return ResponseEntity.ok(authResponse);
    }

    public Map<String, Object> getMapFromIoJsonwebtokenClaims(DefaultClaims claims) {
        Map<String, Object> expectedMap = new HashMap<String, Object>();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            expectedMap.put(entry.getKey(), entry.getValue());
        }
        return expectedMap;
    }

}
