package com.salahin.springsecurity.controllers;

import com.salahin.springsecurity.configuration.CustomAuthenticationManager;
import com.salahin.springsecurity.configuration.CustomUserDetailsService;
import com.salahin.springsecurity.model.UserModel;
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

    private final CustomUserDetailsService userDetailsService;
    private final JwtTokenUtilService jwtTokenUtilService;
    private final CustomAuthenticationManager customAuthenticationManager;
    private final JwtTokenInfoService jwtTokenInfoService;


    public AuthenticationController(
            CustomUserDetailsService userDetailsService,
            JwtTokenUtilService jwtTokenUtilService,
            CustomAuthenticationManager customAuthenticationManager,
            JwtTokenInfoService jwtTokenInfoService) {

        this.userDetailsService = userDetailsService;
        this.jwtTokenUtilService = jwtTokenUtilService;
        this.customAuthenticationManager = customAuthenticationManager;
        this.jwtTokenInfoService = jwtTokenInfoService;
    }

    @PostMapping(value = "/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthRequest authRequest) throws Exception {

      //  UserModel userModel;
        Authentication authenticate;
        authenticate = customAuthenticationManager.authenticate
                (
                        new UsernamePasswordAuthenticationToken
                                (
                                        authRequest.getUsername(),
                                        authRequest.getPassword()
                                )
                );

        Collection<? extends GrantedAuthority> authorities = authenticate.getAuthorities();

        final UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getUsername());
        // Generate jwt token
        AuthResponse authResponse = jwtTokenUtilService.getAccessToken(userDetails.getUsername(), authorities);
        return ResponseEntity.ok(authResponse);
    }


    @PostMapping("/signing-out")
    public ResponseEntity<?> logoutUser(@RequestBody AuthRequest authRequest) {
        this.jwtTokenInfoService.deleteAccessToken(authRequest.getUsername());
        SecurityContextHolder.clearContext();
        return new ResponseEntity<>("User has been logged out successfully", HttpStatus.OK);
    }

}
