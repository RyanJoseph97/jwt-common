package com.eventmaster.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Shared JWT utility for token generation and validation.
 * All services read the same jwt.secret property so tokens issued by
 * user-service can be verified by event-service, recommendation-service, etc.
 */
@Component
public class JwtConfig {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration:86400000}")
    private long jwtExpiration;

    // Constructor for use in unit tests (bypasses Spring field injection).
    // The secret must be at least 32 characters to satisfy HMAC-SHA256.
    public JwtConfig(String secret) {
        this.secret = secret;
        this.jwtExpiration = 86400000;
    }

    // No-arg constructor for Spring (field injection via @Value).
    public JwtConfig() {}

    private Key getSigningKey() {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        return new SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.getJcaName());
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(extractAllClaims(token));
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String generateToken(String username) {
        return generateToken(username, new HashMap<>());
    }

    /**
     * Generates a token with additional claims embedded in the payload.
     * Use this to include domain-specific data (e.g. accountStatus) so
     * downstream services can authorise without calling back to user-service.
     */
    public String generateToken(String username, Map<String, Object> additionalClaims) {
        Map<String, Object> claims = new HashMap<>(additionalClaims);
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Validates the token signature and expiration. Does not check a specific username —
     * call extractUsername() after validation if you need the subject.
     */
    public boolean validateToken(String token) {
        try {
            extractAllClaims(token);
            return !extractExpiration(token).before(new Date());
        } catch (Exception e) {
            return false;
        }
    }
}
