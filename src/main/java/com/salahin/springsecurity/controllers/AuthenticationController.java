package com.salahin.springsecurity.controllers;

import com.salahin.springsecurity.configuration.CustomAuthenticationManager;
import com.salahin.springsecurity.configuration.CustomUserDetailsService;
import com.salahin.springsecurity.service.JwtTokenUtilService;
import com.salahin.springsecurity.model.AuthRequest;
import com.salahin.springsecurity.model.AuthResponse;
import com.salahin.springsecurity.service.JwtTokenInfoService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;


@RestController
public class AuthenticationController {

    private final CustomUserDetailsService customUserDetailsService;
    private final JwtTokenUtilService jwtTokenUtilService;
    private final CustomAuthenticationManager customAuthenticationManager;
    private final JwtTokenInfoService jwtTokenInfoService;



    public AuthenticationController(
            CustomUserDetailsService customUserDetailsService,
            JwtTokenUtilService jwtTokenUtilService,
            CustomAuthenticationManager customAuthenticationManager,
            JwtTokenInfoService jwtTokenInfoService) {

        this.customUserDetailsService = customUserDetailsService;
        this.jwtTokenUtilService = jwtTokenUtilService;
        this.customAuthenticationManager = customAuthenticationManager;
        this.jwtTokenInfoService = jwtTokenInfoService;
    }

    @PostMapping(value = "/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthRequest authRequest) throws Exception {
        Authentication authenticate = customAuthenticationManager.authenticate
                (
                        new UsernamePasswordAuthenticationToken
                                (
                                        authRequest.getUsername(),
                                        authRequest.getPassword()
                                )
                );


        Collection<? extends GrantedAuthority> authorities = authenticate.getAuthorities();
        Object credentials = authenticate.getCredentials();
        User user = (User) authenticate.getPrincipal();

        //final UserDetails userDetails = userDetailsService.loadUserByUsername(credentials.toString());
        // Generate jwt token
        AuthResponse authResponse = jwtTokenUtilService.getAccessToken(user.getUsername(), authorities);
        return ResponseEntity.ok(authResponse);
    }

   /* @GetMapping(value = "/refreshtoken")
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
    }*/

    @PostMapping("/signing-out")
    public ResponseEntity<?> logoutUser(@RequestBody AuthRequest authRequest) {
        this.jwtTokenInfoService.deleteAccessToken(authRequest.getUsername());
        SecurityContextHolder.clearContext();
        return new ResponseEntity<>("User has been logged out successfully", HttpStatus.OK);
    }

}
