package com.salahin.springsecurity.configuration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CustomAuthenticationManagerTest {
    private final UserDetailsService users = mock(UserDetailsService.class);
    private final PasswordEncoder encoder = mock(PasswordEncoder.class);
    private CustomAuthenticationManager manager;

    @BeforeEach
    void setup() {
        manager = new CustomAuthenticationManager();
        ReflectionTestUtils.setField(manager, "userDetailsService", users);
        ReflectionTestUtils.setField(manager, "passwordEncoder", encoder);
    }

    @Test
    void validCredentialsAuthenticateWithoutRetainingRawPassword() {
        UserDetails user = User.withUsername("alice").password("encoded").roles("USER").build();
        when(users.loadUserByUsername("alice")).thenReturn(user);
        when(encoder.matches("secret", "encoded")).thenReturn(true);

        Authentication result = manager.authenticate(
                new UsernamePasswordAuthenticationToken("alice", "secret"));

        assertTrue(result.isAuthenticated());
        assertEquals("alice", result.getName());
        assertNull(result.getCredentials());
        assertTrue(result.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_USER")));
    }

    @Test
    void invalidPasswordIsRejected() {
        when(users.loadUserByUsername("alice")).thenReturn(
                User.withUsername("alice").password("encoded").roles("USER").build());
        when(encoder.matches("wrong", "encoded")).thenReturn(false);

        assertThrows(BadCredentialsException.class, () -> manager.authenticate(
                new UsernamePasswordAuthenticationToken("alice", "wrong")));
    }

    @Test
    void disabledUserIsRejectedBeforePasswordCheck() {
        when(users.loadUserByUsername("alice")).thenReturn(
                User.withUsername("alice").password("encoded").roles("USER").disabled(true).build());

        assertThrows(DisabledException.class, () -> manager.authenticate(
                new UsernamePasswordAuthenticationToken("alice", "secret")));
        verifyNoInteractions(encoder);
    }
}
