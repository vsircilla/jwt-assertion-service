# JWT Assertion Service

A Spring Boot application that validates Microsoft Entra (Azure AD) JWT tokens and generates new signed JWT assertions for backend services like ServiceNow.

## Architecture Flow

```
User Client --> [Entra JWT] --> JWT Assertion Service --> [Signed Assertion] --> ServiceNow
                     |                                              |
                     v                                              v
              (Validate)                                   (Exchange for Access Token)
```

## Features

- **Microsoft Entra JWT Validation**: Validates incoming JWT tokens from Azure AD/Entra ID
- **JWT Assertion Generation**: Creates new JWT assertions signed with an RSA private key (RS256)
- **ServiceNow Integration**: Exchanges assertions for ServiceNow access tokens
- **Configurable**: Fully configurable via environment variables or `application.yml`

## Prerequisites

- Java 17 or higher
- Maven 3.8+
- OpenSSL (for key generation)

## Setup

### 1. Generate RSA Key Pair

```bash
./scripts/generate-key.sh
```

This generates a 2048-bit RSA private key at `src/main/resources/keys/private-key.pem`.

Extract the public key for ServiceNow configuration:

```bash
openssl pkey -in src/main/resources/keys/private-key.pem \
    -pubout -out src/main/resources/keys/private-key-public.pem
```

### 2. Configure Environment Variables

Create a `.env` file or set these environment variables:

```bash
# Microsoft Entra (Azure AD) Configuration
export ENTRA_TENANT_ID="your-azure-ad-tenant-id"
export ENTRA_CLIENT_ID="your-azure-ad-application-client-id"

# Signing Configuration
export SIGNING_PRIVATE_KEY_PATH="./src/main/resources/keys/private-key.pem"
export SIGNING_KEY_ID="assertion-key-1"

# ServiceNow Configuration
export SERVICENOW_INSTANCE_URL="https://your-instance.service-now.com"
export SERVICENOW_CLIENT_ID="your-servicenow-integration-client-id"
export SERVICENOW_USERNAME="your-service-username"
export SERVICENOW_PASSWORD="your-service-password"
export SERVICENOW_SCOPE="your-scopes"
```

### 3. Build and Run

```bash
mvn clean package
java -jar target/jwt-assertion-service-1.0.0.jar
```

Or using Maven:

```bash
mvn spring-boot:run
```

## API Endpoints

### Generate JWT Assertion

```bash
curl -X POST http://localhost:8080/api/assertion \
  -H "Authorization: Bearer <MICROSOFT_ENTRA_JWT>"
```

**Response:**

```json
{
  "assertion": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFzc2VydGlvbi1rZXktMSJ9...",
  "validatedClaims": {
    "subject": "user-subject-id",
    "email": "user@example.com",
    "username": "user@example.com",
    "tenantId": "azure-tenant-id"
  }
}
```

### Exchange for ServiceNow Token

```bash
curl -X POST http://localhost:8080/api/servicenow/token \
  -H "Authorization: Bearer <MICROSOFT_ENTRA_JWT>"
```

**Response:**

```json
{
  "servicenowToken": {
    "accessToken": "servicenow-access-token",
    "tokenType": "Bearer",
    "expiresIn": "3600",
    "scope": "your-scopes"
  },
  "validatedClaims": {
    "subject": "user-subject-id",
    "email": "user@example.com"
  }
}
```

### Health Check

```bash
curl http://localhost:8080/api/health
```

## Configuration Reference

| Property | Description | Default |
|----------|-------------|---------|
| `jwt-assertion.entra.tenant-id` | Azure AD Tenant ID | - |
| `jwt-assertion.entra.client-id` | Azure AD Application Client ID | - |
| `jwt-assertion.entra.issuer` | Trusted issuer URL | `https://login.microsoftonline.com/{tenant-id}/v2.0` |
| `jwt-assertion.signing.private-key-path` | Path to RSA private key PEM file | `./keys/private-key.pem` |
| `jwt-assertion.signing.key-id` | Key identifier for the signing key | `assertion-key-1` |
| `jwt-assertion.servicenow.instance-url` | ServiceNow instance URL | - |
| `jwt-assertion.servicenow.client-id` | ServiceNow integration client ID | - |
| `jwt-assertion.servicenow.username` | ServiceNow username | - |
| `jwt-assertion.servicenow.password` | ServiceNow password | - |

## Project Structure

```
src/main/java/com/example/jwtassertion/
├── JwtAssertionApplication.java    # Main Spring Boot class
├── config/
│   ├── JwtAssertionProperties.java  # Configuration properties
│   └── SecurityConfig.java          # Spring Security config
├── controller/
│   └── JwtAssertionController.java  # REST endpoints
└── service/
    ├── EntraJwtValidator.java       # Validates Microsoft Entra JWTs
    ├── AssertionGenerator.java      # Generates signed JWT assertions
    └── ServiceNowClient.java        # ServiceNow token exchange
```

## Security Notes

- The private key should be stored securely and never committed to version control
- Use environment variables for sensitive configuration values
- Consider using a secrets management solution (HashiCorp Vault, Azure Key Vault, etc.)
- The ServiceNow password should never be hardcoded
