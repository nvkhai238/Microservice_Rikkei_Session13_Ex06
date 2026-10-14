package com.rikkei.product;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/products")
public class ProductController {
    @GetMapping
    public List<Map<String, Object>> products(@RequestHeader("X-User-Id") String userId) {
        return List.of(Map.of("id", "demo-1", "name", "Laptop demo", "requestedBy", userId));
    }

    @PostMapping
    public ResponseEntity<?> create(@RequestHeader("X-User-Role") String role,
                                    @RequestHeader("X-User-Id") String userId,
                                    @Valid @RequestBody ProductRequest request) {
        if (!"ADMIN".equals(role)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "Forbidden"));
        }
        return ResponseEntity.ok(Map.of("id", UUID.randomUUID().toString(),
            "name", request.name(), "createdBy", userId));
    }

    public record ProductRequest(@NotBlank String name) {}
}
