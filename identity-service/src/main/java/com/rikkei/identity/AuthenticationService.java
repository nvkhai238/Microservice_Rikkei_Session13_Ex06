package com.rikkei.identity;

import java.util.UUID;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthenticationService {
    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthenticationService(UserRepository users, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @Transactional(readOnly = true)
    public TokenResponse login(LoginRequest request) {
        if (request.username() == null || request.username().isBlank()
            || request.password() == null || request.password().isBlank()) {
            throw new BadCredentialsException("Bad credentials");
        }
        User user = users.findByUsername(request.username())
            .orElseThrow(() -> new BadCredentialsException("Bad credentials"));
        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new BadCredentialsException("Bad credentials");
        }
        return new TokenResponse(jwtUtil.generateToken(user));
    }

    @Transactional
    public UserResponse register(RegisterRequest request) {
        String username = request.username().trim();
        if (users.existsByUsername(username)) {
            throw new DuplicateUsernameException();
        }
        User user = new User(UUID.randomUUID().toString(), username,
            passwordEncoder.encode(request.password()), "USER");
        return UserResponse.from(users.save(user));
    }
}
