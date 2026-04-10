package com.playground.springSecurity.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JWTUtils {

    private final String SIGNATURE = "my-secret-key-for-jwt-123456789@";
    private final SecretKey key = Keys.hmacShaKeyFor(SIGNATURE.getBytes());

    public String generateToken(String username) {
        int EXPIRATION_TIME = 1000 * 60 * 60; // 1 hour
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(key)
                .compact();
    }

    public boolean verifyToken(AppUserDetails userDetails, String token) {
        return userDetails.getUsername().equals(extractUsernameFromToken(token));
    }

    public String extractUsernameFromToken(String token) {
        // checks the integrity
        // exp time of the token
        // gets the username
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }
}
