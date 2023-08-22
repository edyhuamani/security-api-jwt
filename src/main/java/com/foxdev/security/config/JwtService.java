package com.foxdev.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";

    /**
     * Permite obtener el nombre de usuario
     * @param token
     * @return
     */
    public String extractUserName(String token){
        return extractClaim(token,claims -> claims.getSubject());
    }

    /**
     * Permite obtener el claim
     * @param token
     * @param claimsResolver
     * @param <T>
     * @return
     */
    public <T> T extractClaim(String token , Function<Claims, T>  claimsResolver){
        final Claims claims =extractAllclaims(token);
        return claimsResolver.apply(claims);
    }


    /**
     * Permite obtener los reclamos / claims
     * @param token
     * @return
     */
    private Claims extractAllclaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Permite obtener la firma
     * @return
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}