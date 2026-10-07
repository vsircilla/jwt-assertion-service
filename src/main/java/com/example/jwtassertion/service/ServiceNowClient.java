package com.example.jwtassertion.service;

import com.example.jwtassertion.config.JwtAssertionProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class ServiceNowClient {

    private static final Logger log = LoggerFactory.getLogger(ServiceNowClient.class);

    private final JwtAssertionProperties properties;
    private final RestTemplate restTemplate;

    public ServiceNowClient(JwtAssertionProperties properties) {
        this.properties = properties;
        this.restTemplate = new RestTemplate();
    }

    /**
     * Exchange a JWT assertion for a ServiceNow access token
     * Uses OAuth 2.0 Token Exchange (RFC 8693) or ServiceNow's custom endpoint
     */
    public ServiceNowTokenResponse exchangeAssertionForToken(String assertion) {
        String tokenUrl = properties.getServicenow().getInstanceUrl() + properties.getServicenow().getTokenEndpoint();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // Build the token request body
        String body = buildTokenRequestBody(assertion);

        HttpEntity<String> request = new HttpEntity<>(body, headers);

        try {
            log.info("Sending token request to ServiceNow: {}", tokenUrl);
            ResponseEntity<String> response = restTemplate.exchange(
                    tokenUrl,
                    HttpMethod.POST,
                    request,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                ServiceNowTokenResponse tokenResponse = parseTokenResponse(response.getBody());
                log.info("Successfully obtained access token from ServiceNow");
                return tokenResponse;
            } else {
                log.error("ServiceNow returned non-success status: {}", response.getStatusCode());
                throw new RuntimeException("ServiceNow token request failed with status: " + response.getStatusCode());
            }

        } catch (Exception e) {
            log.error("Failed to exchange assertion for ServiceNow token", e);
            throw new RuntimeException("Failed to exchange assertion for token: " + e.getMessage(), e);
        }
    }

    /**
     * Alternative: Direct JWT bearer token grant to ServiceNow
     */
    public ServiceNowTokenResponse exchangeWithBearerGrant(String assertion) {
        String tokenUrl = properties.getServicenow().getInstanceUrl() + "/api/x_your_module/oauth_token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String body = String.format(
                "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" +
                "&assertion=%s" +
                "&client_id=%s" +
                "&username=%s",
                urlEncode(assertion),
                properties.getServicenow().getClientId(),
                properties.getServicenow().getUsername()
        );

        if (properties.getServicenow().getScope() != null && !properties.getServicenow().getScope().isEmpty()) {
            body += "&scope=" + urlEncode(properties.getServicenow().getScope());
        }

        HttpEntity<String> request = new HttpEntity<>(body, headers);

        try {
            log.info("Sending bearer grant token request to ServiceNow: {}", tokenUrl);
            ResponseEntity<String> response = restTemplate.exchange(
                    tokenUrl,
                    HttpMethod.POST,
                    request,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return parseTokenResponse(response.getBody());
            } else {
                throw new RuntimeException("ServiceNow token request failed: " + response.getBody());
            }

        } catch (Exception e) {
            log.error("Failed to exchange assertion using bearer grant", e);
            throw new RuntimeException("Failed to exchange assertion: " + e.getMessage(), e);
        }
    }

    private String buildTokenRequestBody(String assertion) {
        return String.format(
                "assertion=%s&client_id=%s&username=%s&grant_type=client_credentials",
                urlEncode(assertion),
                properties.getServicenow().getClientId(),
                properties.getServicenow().getUsername()
        );
    }

    private ServiceNowTokenResponse parseTokenResponse(String responseBody) {
        try {
            // Simple JSON parsing - in production, use Jackson ObjectMapper
            ServiceNowTokenResponse response = new ServiceNowTokenResponse();
            response.setAccessToken(extractJsonValue(responseBody, "access_token"));
            response.setTokenType(extractJsonValue(responseBody, "token_type"));
            response.setExpiresIn(extractJsonValue(responseBody, "expires_in"));
            response.setScope(extractJsonValue(responseBody, "scope"));
            return response;
        } catch (Exception e) {
            // Fall back to simple parsing
            ServiceNowTokenResponse response = new ServiceNowTokenResponse();
            response.setAccessToken(extractJsonValue(responseBody, "access_token"));
            response.setTokenType(extractJsonValue(responseBody, "token_type"));
            response.setExpiresIn(extractJsonValue(responseBody, "expires_in"));
            response.setScope(extractJsonValue(responseBody, "scope"));
            return response;
        }
    }

    private String extractJsonValue(String json, String key) {
        String search = "\"" + key + "\"";
        int startIndex = json.indexOf(search);
        if (startIndex == -1) return null;

        int colonIndex = json.indexOf(":", startIndex) + 1;
        int stringStart = json.indexOf("\"", colonIndex) + 1;
        int stringEnd = json.indexOf("\"", stringStart);

        return json.substring(stringStart, stringEnd);
    }

    private String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * Response from ServiceNow token exchange
     */
    public static class ServiceNowTokenResponse {
        private String accessToken;
        private String tokenType;
        private String expiresIn;
        private String scope;

        // Getters and setters
        public String getAccessToken() { return accessToken; }
        public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
        public String getTokenType() { return tokenType; }
        public void setTokenType(String tokenType) { this.tokenType = tokenType; }
        public String getExpiresIn() { return expiresIn; }
        public void setExpiresIn(String expiresIn) { this.expiresIn = expiresIn; }
        public String getScope() { return scope; }
        public void setScope(String scope) { this.scope = scope; }
    }
}
