package com.rikkei.identity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

class AuthenticationServiceTest {
    @Test
    void loginAcceptsMatchingPasswordAndRejectsBothKindsOfBadCredentials() {
        UserRepository users = mock(UserRepository.class);
        JwtUtil jwtUtil = mock(JwtUtil.class);
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        User user = new User("id-1", "alice", encoder.encode("password123"), "USER");
        when(users.findByUsername("alice")).thenReturn(Optional.of(user));
        when(users.findByUsername("missing")).thenReturn(Optional.empty());
        when(jwtUtil.generateToken(user)).thenReturn("jwt");
        AuthenticationService service = new AuthenticationService(users, encoder, jwtUtil);

        assertEquals("jwt", service.login(new LoginRequest("alice", "password123")).accessToken());
        assertEquals("Bad credentials", assertThrows(BadCredentialsException.class,
            () -> service.login(new LoginRequest("alice", "wrong"))).getMessage());
        assertEquals("Bad credentials", assertThrows(BadCredentialsException.class,
            () -> service.login(new LoginRequest("missing", "password123"))).getMessage());
        verify(jwtUtil, times(1)).generateToken(user);
    }
}
