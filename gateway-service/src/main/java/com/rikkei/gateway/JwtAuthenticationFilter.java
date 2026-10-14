package com.rikkei.gateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {
    private final Key key;
    private final byte[] internalSecret;

    public JwtAuthenticationFilter(@Value("${jwt.secret}") String secret,
                                   @Value("${gateway.internal-secret}") String internalSecret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.internalSecret = internalSecret.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public int getOrder() { return -100; }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest cleanRequest = exchange.getRequest().mutate().headers(headers -> {
            headers.remove("X-User-Id");
            headers.remove("X-User-Role");
            headers.remove("X-Gateway-Timestamp");
            headers.remove("X-Gateway-Signature");
        }).build();
        ServerWebExchange cleanExchange = exchange.mutate().request(cleanRequest).build();
        String path = cleanRequest.getURI().getRawPath();
        if (path.startsWith("/identity/api/auth/")) {
            return chain.filter(cleanExchange);
        }
        String authorization = cleanRequest.getHeaders().getFirst("Authorization");
        if (authorization == null || !authorization.startsWith("Bearer ") || authorization.length() <= 7) {
            return unauthorized(cleanExchange);
        }
        try {
            Claims claims = Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(authorization.substring(7)).getBody();
            String userId = claims.get("userId", String.class);
            String role = claims.get("role", String.class);
            if (claims.getSubject() == null || userId == null || role == null) {
                return unauthorized(cleanExchange);
            }
            if (!path.startsWith("/products/")) {
                return chain.filter(cleanExchange);
            }
            String timestamp = Long.toString(Instant.now().getEpochSecond());
            String downstreamPath = path.substring("/products".length());
            String signature = sign(cleanRequest.getMethod().name(), downstreamPath, userId, role, timestamp);
            ServerHttpRequest signedRequest = cleanRequest.mutate().headers(headers -> {
                headers.set("X-User-Id", userId);
                headers.set("X-User-Role", role);
                headers.set("X-Gateway-Timestamp", timestamp);
                headers.set("X-Gateway-Signature", signature);
            }).build();
            return chain.filter(cleanExchange.mutate().request(signedRequest).build());
        } catch (JwtException | IllegalArgumentException exception) {
            return unauthorized(cleanExchange);
        }
    }

    private String sign(String method, String path, String userId, String role, String timestamp) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(internalSecret, "HmacSHA256"));
            String message = String.join("\n", method, path, userId, role, timestamp);
            return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("Cannot sign user context", exception);
        }
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        byte[] body = "{\"error\":\"Unauthorized\"}".getBytes(StandardCharsets.UTF_8);
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(body)));
    }
}
