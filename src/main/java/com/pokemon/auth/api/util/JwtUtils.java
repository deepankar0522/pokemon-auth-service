package com.pokemon.auth.api.util;

import com.pokemon.auth.api.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {

    @Value("${security.jwt.secret-key}")
    private String jwtSecret;

    @Value("${security.jwt.expiration-time}")
    private int jwtExpirationMs;

    private static final Logger log = LoggerFactory.getLogger(JwtUtils.class);


    public String generateJwtToken(UserDetailsImpl userDetails) {
        return Jwts.builder()
                .setSubject((userDetails.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(getSignInKey())
                .compact();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
             log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
             log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
             log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
             log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
             log.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}
