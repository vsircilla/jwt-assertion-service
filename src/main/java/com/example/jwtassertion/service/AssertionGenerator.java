package com.example.jwtassertion.service;

import com.example.jwtassertion.config.JwtAssertionProperties;
import com.example.jwtassertion.service.EntraJwtValidator.ValidatedEntraClaims;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class AssertionGenerator {

    private static final Logger log = LoggerFactory.getLogger(AssertionGenerator.class);

    private final JwtAssertionProperties properties;
    private RSAPrivateKey privateKey;

    public AssertionGenerator(JwtAssertionProperties properties) throws Exception {
        this.properties = properties;
        this.privateKey = loadPrivateKey(properties.getSigning().getPrivateKeyPath());
        log.info("Loaded signing private key from: {}", properties.getSigning().getPrivateKeyPath());
    }

    private RSAPrivateKey loadPrivateKey(String keyPath) throws Exception {
        String keyContent = new String(Files.readAllBytes(Paths.get(keyPath)), StandardCharsets.UTF_8);

        // Remove PEM headers/footers and newlines
        String pemKey = keyContent
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] encoded = Base64.getDecoder().decode(pemKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(spec);
    }

    public String generateAssertion(ValidatedEntraClaims entraClaims) {
        String audience = properties.getServicenow().getInstanceUrl();
        String issuer = properties.getEntra().getClientId();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject(entraClaims.getSubject())
                .claim("email", entraClaims.getEmail())
                .claim("oid", entraClaims.getObjectId())
                .claim("tid", entraClaims.getTenantId())
                .claim("preferred_username", entraClaims.getUsername())
                .claim("roles", entraClaims.getRoles() != null ? entraClaims.getRoles() : List.<String>of())
                .expirationTime(Date.from(Instant.now().plus(java.time.Duration.ofMinutes(5))))
                .issueTime(Date.from(Instant.now()))
                .notBeforeTime(Date.from(Instant.now()))
                .jwtID(UUID.randomUUID().toString())
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(properties.getSigning().getKeyId())
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        try {
            RSASSASigner signer = new RSASSASigner(privateKey);
            signedJWT.sign(signer);

            String assertion = signedJWT.serialize();
            log.info("Successfully generated JWT assertion for subject: {}", entraClaims.getSubject());
            return assertion;

        } catch (com.nimbusds.jose.JOSEException e) {
            log.error("Failed to sign JWT assertion", e);
            throw new RuntimeException("Failed to sign JWT assertion", e);
        }
    }

    public String generateAssertion(ValidatedEntraClaims entraClaims, Map<String, Object> additionalClaims) {
        String baseAssertion = generateAssertion(entraClaims);

        // Parse and add additional claims if needed
        try {
            SignedJWT signedJWT = SignedJWT.parse(baseAssertion);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder(claims);
            if (additionalClaims != null) {
                additionalClaims.forEach(builder::claim);
            }

            JWTClaimsSet updatedClaims = builder.build();
            JWSHeader header = signedJWT.getHeader();

            SignedJWT updatedJWT = new SignedJWT(header, updatedClaims);
            RSASSASigner signer = new RSASSASigner(privateKey);
            updatedJWT.sign(signer);

            log.info("Successfully generated JWT assertion with additional claims");
            return updatedJWT.serialize();

        } catch (Exception e) {
            log.error("Failed to add additional claims, returning base assertion", e);
            return baseAssertion;
        }
    }
}
