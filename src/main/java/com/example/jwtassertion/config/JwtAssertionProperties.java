package com.example.jwtassertion.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt-assertion")
public class JwtAssertionProperties {

    private EntraConfig entra = new EntraConfig();
    private SigningConfig signing = new SigningConfig();
    private ServiceNowConfig servicenow = new ServiceNowConfig();

    public EntraConfig getEntra() {
        return entra;
    }

    public void setEntra(EntraConfig entra) {
        this.entra = entra;
    }

    public SigningConfig getSigning() {
        return signing;
    }

    public void setSigning(SigningConfig signing) {
        this.signing = signing;
    }

    public ServiceNowConfig getServicenow() {
        return servicenow;
    }

    public void setServicenow(ServiceNowConfig servicenow) {
        this.servicenow = servicenow;
    }

    public static class EntraConfig {
        private String tenantId;
        private String clientId;
        private String issuer;
        private String jwksUrl;

        public String getTenantId() {
            return tenantId;
        }

        public void setTenantId(String tenantId) {
            this.tenantId = tenantId;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getJwksUrl() {
            return jwksUrl;
        }

        public void setJwksUrl(String jwksUrl) {
            this.jwksUrl = jwksUrl;
        }
    }

    public static class SigningConfig {
        private String privateKeyPath;
        private String keyId;
        private String algorithm;

        public String getPrivateKeyPath() {
            return privateKeyPath;
        }

        public void setPrivateKeyPath(String privateKeyPath) {
            this.privateKeyPath = privateKeyPath;
        }

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }
    }

    public static class ServiceNowConfig {
        private String instanceUrl;
        private String clientId;
        private String username;
        private String password;
        private String tokenEndpoint;
        private String scope;

        public String getInstanceUrl() {
            return instanceUrl;
        }

        public void setInstanceUrl(String instanceUrl) {
            this.instanceUrl = instanceUrl;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getTokenEndpoint() {
            return tokenEndpoint;
        }

        public void setTokenEndpoint(String tokenEndpoint) {
            this.tokenEndpoint = tokenEndpoint;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }
    }
}
