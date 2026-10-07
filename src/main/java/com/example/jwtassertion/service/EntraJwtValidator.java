package com.example.jwtassertion.service;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.example.jwtassertion.config.JwtAssertionProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;

@Service
public class EntraJwtValidator {

    private static final Logger log = LoggerFactory.getLogger(EntraJwtValidator.class);

    private final JwtAssertionProperties properties;

    public EntraJwtValidator(JwtAssertionProperties properties) {
        this.properties = properties;
    }

    public ValidatedEntraClaims validateToken(String token) {
        try {
            SignedJWT signedJWT = (SignedJWT) JWTParser.parse(token);

            // Fetch JWKS and verify signature
            JWKSet jwkSet = fetchJwks();
            
            String keyId = signedJWT.getHeader().getKeyID();
            boolean verified = false;
            RSAPublicKey publicKey = null;

            for (JWK jwk : jwkSet.getKeys()) {
                if (keyId == null || keyId.equals(jwk.getKeyID())) {
                    try {
                        RSAKey rsaKey = (RSAKey) jwk;
                        RSASSAVerifier verifier = new RSASSAVerifier(rsaKey);
                        if (signedJWT.verify(verifier)) {
                            publicKey = (RSAPublicKey) rsaKey.toPublicKey();
                            verified = true;
                            log.debug("Successfully verified with key: {}", rsaKey.getKeyID());
                            break;
                        }
                    } catch (Exception e) {
                        // Try next key
                    }
                }
            }

            if (!verified || publicKey == null) {
                throw new IllegalArgumentException("Invalid token signature");
            }

            // Verify claims
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            verifyClaims(claims);

            ValidatedEntraClaims validatedClaims = new ValidatedEntraClaims();
            validatedClaims.setSubject(claims.getSubject());
            validatedClaims.setEmail(claims.getStringClaim("email"));
            validatedClaims.setObjectId(claims.getStringClaim("oid"));
            validatedClaims.setTenantId(claims.getStringClaim("tid"));
            validatedClaims.setUsername(claims.getStringClaim("preferred_username"));

            // Extract roles if present
            Object rolesObj = claims.getClaim("roles");
            if (rolesObj instanceof List) {
                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) rolesObj;
                validatedClaims.setRoles(roles);
            } else if (rolesObj != null) {
                validatedClaims.setRoles(List.of(rolesObj.toString()));
            }

            log.debug("Successfully validated Entra JWT for subject: {}", validatedClaims.getSubject());
            return validatedClaims;

        } catch (ParseException e) {
            log.error("Failed to parse JWT token", e);
            throw new IllegalArgumentException("Invalid token format", e);
        } catch (Exception e) {
            log.error("Failed to validate JWT token", e);
            throw new IllegalArgumentException("Token validation failed: " + e.getMessage(), e);
        }
    }

    private JWKSet fetchJwks() throws IOException, InterruptedException, ParseException {
        String jwksUrl = properties.getEntra().getJwksUrl();
        
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(jwksUrl))
                .GET()
                .build();
        
        String jwksJson = client.send(request, HttpResponse.BodyHandlers.ofString()).body();
        return JWKSet.parse(jwksJson);
    }

    private void verifyClaims(JWTClaimsSet claims) {
        try {
            String issuer = claims.getStringClaim("iss");
            String expectedIssuer = properties.getEntra().getIssuer();

            if (issuer == null || !issuer.equals(expectedIssuer)) {
                throw new IllegalArgumentException("Invalid issuer: " + issuer);
            }

            String audience = claims.getStringClaim("aud");
            String expectedAudience = properties.getEntra().getClientId();
            if (audience != null && !Arrays.asList(audience.split(",")).contains(expectedAudience)) {
                throw new IllegalArgumentException("Invalid audience: " + audience);
            }

            long expirationTime = claims.getExpirationTime().getTime();
            if (Instant.now().toEpochMilli() > expirationTime) {
                throw new IllegalArgumentException("Token has expired");
            }
        } catch (ParseException e) {
            throw new IllegalArgumentException("Invalid token claims: " + e.getMessage(), e);
        }
    }

    /**
     * Holds the validated claims from the Entra JWT
     */
    public static class ValidatedEntraClaims {
        private String subject;
        private String email;
        private String objectId;
        private String tenantId;
        private String username;
        private List<String> roles;

        // Getters and setters
        public String getSubject() { return subject; }
        public void setSubject(String subject) { this.subject = subject; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public String getObjectId() { return objectId; }
        public void setObjectId(String objectId) { this.objectId = objectId; }
        public String getTenantId() { return tenantId; }
        public void setTenantId(String tenantId) { this.tenantId = tenantId; }
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public List<String> getRoles() { return roles; }
        public void setRoles(List<String> roles) { this.roles = roles; }
    }
}
