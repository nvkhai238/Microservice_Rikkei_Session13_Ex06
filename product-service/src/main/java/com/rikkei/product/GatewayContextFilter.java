package com.rikkei.product;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class GatewayContextFilter extends OncePerRequestFilter {
    private final byte[] internalSecret;

    public GatewayContextFilter(@Value("${gateway.internal-secret}") String secret) {
        this.internalSecret = secret.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String userId = request.getHeader("X-User-Id");
        String role = request.getHeader("X-User-Role");
        String timestamp = request.getHeader("X-Gateway-Timestamp");
        String signature = request.getHeader("X-Gateway-Signature");
        if (!valid(request, userId, role, timestamp, signature)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Unauthorized\"}");
            return;
        }
        chain.doFilter(request, response);
    }

    private boolean valid(HttpServletRequest request, String userId, String role,
                          String timestamp, String signature) {
        if (userId == null || userId.isBlank() || role == null || role.isBlank()
            || timestamp == null || signature == null) {
            return false;
        }
        try {
            long age = Math.abs(Instant.now().getEpochSecond() - Long.parseLong(timestamp));
            if (age > 60) return false;
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(internalSecret, "HmacSHA256"));
            String message = String.join("\n", request.getMethod(), request.getRequestURI(),
                userId, role, timestamp);
            byte[] expected = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            byte[] received = Base64.getUrlDecoder().decode(signature);
            return MessageDigest.isEqual(expected, received);
        } catch (Exception exception) {
            return false;
        }
    }
}
