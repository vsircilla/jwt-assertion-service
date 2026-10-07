package com.example.jwtassertion.controller;

import com.example.jwtassertion.service.EntraJwtValidator;
import com.example.jwtassertion.service.EntraJwtValidator.ValidatedEntraClaims;
import com.example.jwtassertion.service.AssertionGenerator;
import com.example.jwtassertion.service.ServiceNowClient;
import com.example.jwtassertion.service.ServiceNowClient.ServiceNowTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class JwtAssertionController {

    private static final Logger log = LoggerFactory.getLogger(JwtAssertionController.class);

    private final EntraJwtValidator entraJwtValidator;
    private final AssertionGenerator assertionGenerator;
    private final ServiceNowClient servicenowClient;

    public JwtAssertionController(
            EntraJwtValidator entraJwtValidator,
            AssertionGenerator assertionGenerator,
            ServiceNowClient servicenowClient) {
        this.entraJwtValidator = entraJwtValidator;
        this.assertionGenerator = assertionGenerator;
        this.servicenowClient = servicenowClient;
    }

    /**
     * Endpoint to receive a Microsoft Entra JWT and return a signed JWT assertion
     * for use with ServiceNow or other backend services.
     *
     * @param token The Microsoft Entra JWT from the user/client
     * @return A signed JWT assertion that can be used with ServiceNow
     */
    @PostMapping("/assertion")
    public ResponseEntity<AssertionResponse> generateAssertion(
            @RequestHeader("Authorization") String authHeader) {

        String token = extractToken(authHeader);

        try {
            // Step 1: Validate the incoming Entra JWT
            ValidatedEntraClaims validatedClaims = entraJwtValidator.validateToken(token);

            // Step 2: Generate a new signed JWT assertion using our private key
            String assertion = assertionGenerator.generateAssertion(validatedClaims);

            log.info("Generated JWT assertion for subject: {}", validatedClaims.getSubject());

            return ResponseEntity.ok(new AssertionResponse(assertion, validatedClaims));

        } catch (IllegalArgumentException e) {
            log.error("Token validation failed: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(new AssertionResponse(null, null, e.getMessage()));
        }
    }

    /**
     * Endpoint to directly exchange an Entra JWT for a ServiceNow access token
     *
     * @param token The Microsoft Entra JWT from the user/client
     * @return ServiceNow access token response
     */
    @PostMapping("/servicenow/token")
    public ResponseEntity<TokenExchangeResponse> exchangeForServiceNowToken(
            @RequestHeader("Authorization") String authHeader) {

        String token = extractToken(authHeader);

        try {
            // Validate and generate assertion
            ValidatedEntraClaims validatedClaims = entraJwtValidator.validateToken(token);
            String assertion = assertionGenerator.generateAssertion(validatedClaims);

            // Exchange assertion for ServiceNow token
            ServiceNowTokenResponse servicenowToken = servicenowClient.exchangeAssertionForToken(assertion);

            return ResponseEntity.ok(new TokenExchangeResponse(servicenowToken, validatedClaims));

        } catch (IllegalArgumentException e) {
            log.error("Token validation failed: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(new TokenExchangeResponse(null, null, e.getMessage()));
        } catch (Exception e) {
            log.error("Failed to exchange token with ServiceNow", e);
            return ResponseEntity.status(500)
                    .body(new TokenExchangeResponse(null, null, "Failed to obtain ServiceNow token: " + e.getMessage()));
        }
    }

    /**
     * Health check endpoint
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("status", "UP"));
    }

    private String extractToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Authorization header must start with 'Bearer '");
        }
        return authHeader.substring(7);
    }

    /**
     * Response DTO for assertion generation
     */
    public static class AssertionResponse {
        private String assertion;
        private ValidatedClaimsInfo validatedClaims;
        private String error;

        public AssertionResponse(String assertion, ValidatedEntraClaims claims) {
            this.assertion = assertion;
            this.error = null;
            if (claims != null) {
                this.validatedClaims = new ValidatedClaimsInfo(claims);
            }
        }

        public AssertionResponse(String assertion, ValidatedEntraClaims claims, String error) {
            this.assertion = assertion;
            this.validatedClaims = claims != null ? new ValidatedClaimsInfo(claims) : null;
            this.error = error;
        }

        // Getters
        public String getAssertion() { return assertion; }
        public ValidatedClaimsInfo getValidatedClaims() { return validatedClaims; }
        public String getError() { return error; }
    }

    /**
     * Response DTO for token exchange
     */
    public static class TokenExchangeResponse {
        private ServiceNowTokenInfo servicenowToken;
        private ValidatedClaimsInfo validatedClaims;
        private String error;

        public TokenExchangeResponse(ServiceNowClient.ServiceNowTokenResponse token,
                                      ValidatedEntraClaims claims) {
            this.error = null;
            if (token != null) {
                this.servicenowToken = new ServiceNowTokenInfo(token);
            }
            if (claims != null) {
                this.validatedClaims = new ValidatedClaimsInfo(claims);
            }
        }

        public TokenExchangeResponse(ServiceNowClient.ServiceNowTokenResponse token,
                                      ValidatedEntraClaims claims, String error) {
            this.servicenowToken = token != null ? new ServiceNowTokenInfo(token) : null;
            this.validatedClaims = claims != null ? new ValidatedClaimsInfo(claims) : null;
            this.error = error;
        }

        // Getters
        public ServiceNowTokenInfo getServicenowToken() { return servicenowToken; }
        public ValidatedClaimsInfo getValidatedClaims() { return validatedClaims; }
        public String getError() { return error; }
    }

    /**
     * Info about validated claims (sanitized for response)
     */
    public static class ValidatedClaimsInfo {
        private String subject;
        private String email;
        private String username;
        private String tenantId;

        public ValidatedClaimsInfo(ValidatedEntraClaims claims) {
            this.subject = claims.getSubject();
            this.email = claims.getEmail();
            this.username = claims.getUsername();
            this.tenantId = claims.getTenantId();
        }

        // Getters
        public String getSubject() { return subject; }
        public String getEmail() { return email; }
        public String getUsername() { return username; }
        public String getTenantId() { return tenantId; }
    }

    /**
     * ServiceNow token info for response
     */
    public static class ServiceNowTokenInfo {
        private String accessToken;
        private String tokenType;
        private String expiresIn;
        private String scope;

        public ServiceNowTokenInfo(ServiceNowClient.ServiceNowTokenResponse response) {
            this.accessToken = response.getAccessToken();
            this.tokenType = response.getTokenType();
            this.expiresIn = response.getExpiresIn();
            this.scope = response.getScope();
        }

        // Getters
        public String getAccessToken() { return accessToken; }
        public String getTokenType() { return tokenType; }
        public String getExpiresIn() { return expiresIn; }
        public String getScope() { return scope; }
    }
}
