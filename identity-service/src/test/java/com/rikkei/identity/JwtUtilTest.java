package com.rikkei.identity;

import static org.junit.jupiter.api.Assertions.*;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class JwtUtilTest {
    @Test
    void generatedTokenContainsIdentityAndRole() {
        String secret = "bA9pD4vE7fG2hJ5kL8mN1qR6sT3uW0xY";
        User user = new User("id-1", "alice", "hash", "ADMIN");
        String token = new JwtUtil(secret, 3600000).generateToken(user);
        Claims claims = Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)))
            .build().parseClaimsJws(token).getBody();
        assertEquals("alice", claims.getSubject());
        assertEquals("id-1", claims.get("userId", String.class));
        assertEquals("ADMIN", claims.get("role", String.class));
        assertTrue(claims.getExpiration().after(claims.getIssuedAt()));
    }
}
