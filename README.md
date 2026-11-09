# Spring Boot 3 Security with JWT

A Spring Boot 3 sample project using Spring Security and JSON Web Tokens (JWT).

## Technology

- Java 17
- Spring Boot 3.3.5
- Spring Security
- Spring Data JPA
- MySQL
- JJWT 0.11.5
- Maven

## Build and test

Use Java 17 and a working Maven installation.

```bash
mvn clean verify
```

The application uses MySQL. Configure the database connection before starting the application. Tests that require a database may need additional setup.

## Example user registration payload

```json
{
  "username": "tuli",
  "password": "replace-with-a-secure-password",
  "roleList": [
    {
      "roleName": "ROLE_USER"
    }
  ]
}
```

Use this JSON body with the application's registration endpoint. Confirm the actual endpoint path in the controller before sending the request.

## Refresh-token request example

```bash
curl --request GET 'http://localhost:8080/refreshtoken' \
  --header 'Authorization: Bearer <your-jwt-token>' \
  --header 'isRefreshToken: true'
```

Replace `<your-jwt-token>` with a token issued by your running application. The header and endpoint shown here reflect the existing README example; verify the implementation before relying on this flow.

## Security notes

- Never commit real passwords, signing keys, or access tokens.
- Use environment-specific configuration for credentials.
- The sample request bodies are for local development and testing, not production credentials.
