# API Broken Authentication

|ID          |
|------------|
|WSTG-APIT-04|

## Summary

**Broken Authentication** vulnerabilities occur when an API improperly implements or enforces authentication mechanisms, allowing attackers to bypass authentication, take over user accounts, or access sensitive information without valid credentials. This may include flaws in session management, credential storage, password reset mechanisms, or token-based authentication.

Common issues that lead to broken authentication include:

- Weak or missing password policies
- Misconfigured token-based authentication (e.g., JWT)
- Lack of multi-factor authentication (MFA)
- Weak or vulnerable password recovery processes

### Risks

Exploiting broken authentication can lead to severe consequences such as:

- **Account takeovers**: Attackers can gain unauthorized access to user accounts, potentially leading to data theft, unauthorized transactions, or manipulation of sensitive information.
- **Privilege escalation**: Attackers might escalate their privileges by exploiting flaws in the authentication mechanism, allowing access to sensitive resources.

## Test Objectives

The objective of this test is to verify that the API enforces strong and secure authentication mechanisms, ensuring only authorized users can access protected resources. The test should also ensure that the API is resistant to common authentication attacks, such as brute force, session hijacking, or token manipulation.

## How to Test for Broken Authentication

### Step 1: Test Authentication Mechanism (Login Flow)

- Identify the **login endpoints** by reviewing API documentation or observing API traffic. Common endpoints include `/login`, `/auth`, `/token`, or `/authenticate`.

- **Test for Weak Password Policies**:
  - Try logging in using weak passwords (e.g., `password123`, `123456`, or `admin`).
  - Check if the API enforces **minimum password length**, **complexity requirements** (e.g., requiring uppercase, numbers, symbols), and prevents the use of **common passwords**.

- **Test for Username Enumeration**:
  - Send invalid login requests using both valid and invalid usernames and observe the API's response.
    - Example: 
      ```
      POST /login
      { "username": "invalid_user", "password": "randompass" }
      ```
    - If the API provides distinct error messages for valid vs. invalid usernames (e.g., "Invalid username" vs. "Invalid password"), this allows attackers to enumerate usernames and indicates a vulnerability.

- **Test for Brute Force Protection**:
  - Attempt to log in with various password combinations using tools like **Burp Suite**, **Hydra**, or **ZAP** to simulate brute force attacks.
  - The API should implement **rate-limiting** or account lockout mechanisms after a certain number of failed login attempts.

### Step 2: Test for Session Management Flaws

- **Session Token Security**:
  - Verify if the API uses **secure session tokens**, such as **JWT** (JSON Web Tokens), and ensure tokens are sufficiently **random and unguessable**.
  - Ensure that tokens are transmitted securely via **HTTPS** and are stored securely on the client-side (e.g., using `HttpOnly` and `Secure` flags for cookies).

- **Test for Session Expiration**:
  - Log in to the API and leave the session idle for a while (e.g., 10-15 minutes).
  - After the session expires, attempt to use the old session token to access protected resources. The API should invalidate the session and require re-authentication.

### Step 3: Test for Token-Based Authentication Issues

#### JWT Token Validation and Token Forgery

- **JWT Token Validation**:
  - If the API uses **JWT tokens**, ensure that the tokens are properly signed and validated.
  - **Modify the token’s signature** and try to authenticate with the tampered token. The API should reject any tampered or unsigned JWT tokens.
  
- **Token Forgery (Unsigned JWT)**:
  - Test if the API accepts **unsigned JWT tokens**. Some misconfigured APIs may accept a JWT token even without verifying the signature, which allows attackers to forge tokens.
  - **Test for Forged JWT** by removing or manipulating the signature portion of the token:
    1. **Create a valid JWT** by logging in with valid credentials.
    2. **Modify the JWT** payload (e.g., change `"role": "user"` to `"role": "admin"`).
    3. Remove the signature and send the modified token to access protected resources.
      ```plaintext
      Header.Payload.
      {
        "user": "regularUser",
        "role": "admin"
      }
      ```

    4. If the API allows access with the forged token (without validating the signature), this indicates a critical vulnerability.

- **Algorithm Manipulation in JWT (None Algorithm)**:
  - Check if the API is vulnerable to **JWT algorithm manipulation**. Some poorly configured APIs may accept JWT tokens signed with a **none algorithm** (i.e., no signing).
    - Modify the token’s `alg` field in the header from `HS256` to `none`.
    - Remove the signature and send the altered JWT to the API. If the API accepts the token without signature verification, it is vulnerable to **token forgery**.
    - Example of manipulated JWT header:
      ```json
      {
        "alg": "none",
        "typ": "JWT"
      }
      ```

- **Test for Weak or Hardcoded Signing Keys**:
  - If the JWT uses a **weak signing key** or a commonly used value (e.g., `secret`), try to brute force or guess the key to forge a valid token.
  - Use tools such as **jwt-cracker** or **Hashcat** to identify weak keys.

- **Test for Token Expiration**:
  - Check if the API respects the **expiration** (`exp`) claim in JWT tokens.
  - Use an expired JWT token to access resources. The API should return a **401 Unauthorized** error.

- **Test for Token Revocation**:
  - Ensure that the API has a **mechanism to revoke tokens** when a user logs out or when tokens are no longer valid. Try to reuse a token after logging out to verify that the token has been invalidated.

### Step 4: Test Password Reset Functionality

- **Weakness in Password Reset Mechanisms**:
  - Request a password reset and check if the API reveals any sensitive information, such as the presence of a valid user account.
  - Ensure the API sends **password reset links** securely (via email or other secure mechanisms) and that reset tokens are time-limited.
  - Try using a previously generated password reset token after it expires. The API should reject expired tokens.

- **Test for Account Recovery Weaknesses**:
  - Ensure that the account recovery process (if present) uses secure challenge-response mechanisms, such as email verification or MFA, to prevent unauthorized account takeovers.

### Step 5: Test for Multi-Factor Authentication (MFA)

- **Check for MFA Enforcement**:
  - Ensure that the API supports **multi-factor authentication (MFA)**, especially for high-privilege or sensitive accounts.
  - Test if MFA can be bypassed or disabled through API endpoints.

### Step 6: Test for OAuth/OpenID Connect Misconfigurations

- **OAuth/OpenID Connect Misconfigurations**:
  - If the API implements **OAuth** or **OpenID Connect**, ensure that the configuration adheres to security best practices:
    - Ensure **secure redirect URIs** are enforced to prevent redirect attacks.
    - Test for vulnerabilities such as **open redirects**, **token leakage** via URL parameters, or **improper scopes** allowing unintended access to resources.

## Indicators of Broken Authentication

- **Weak or No Authentication**: Users can access protected resources without providing valid credentials.
- **Insecure Token Handling**: Session tokens are predictable, not securely transmitted (e.g., over HTTP), or can be reused after logout.
- **Weak Password Policies**: The API allows weak passwords or does not enforce complexity requirements.
- **Lack of Account Lockout**: The API allows unlimited login attempts without rate-limiting or lockout, facilitating brute force attacks.
- **Token Replay or Tampering**: The API accepts tampered or replayed tokens without proper validation.
- **Token Forgery**: The API accepts unsigned or weakly signed JWT tokens, allowing attackers to forge tokens and gain unauthorized access.

## Remediations

To prevent broken authentication vulnerabilities, implement the following best practices:

- **Enforce Strong Password Policies**: Require passwords of sufficient length and complexity, and avoid allowing common passwords.
- **Rate-Limiting and Lockout Mechanisms**: Implement rate-limiting and lockout mechanisms after repeated failed login attempts to prevent brute force.
- **Follow security practices for JWT/OAuth/OpenID**: Follow security practices when utilizing Oauth/OpenID standards and JWT tokens.

## Tools

- **Burp Suite**: Use **Intruder** or **Repeater** to test authentication endpoints for vulnerabilities such as weak passwords, brute force, and token manipulation.
- **Hydra**: A powerful tool to automate brute force attacks against login endpoints.
- **Postman**: Manually test API requests for authentication flaws.
- **ZAP**: Automated scans and manual testing for broken authentication vulnerabilities.
- **JWT.io**: For decoding and tampering with JWT tokens to test for validation flaws.
- **jwt-cracker**: A tool to brute force JWT secret keys to test for weak signing keys.

## References

- [OWASP API Security Top 10: Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/) 
- [OWASP Testing Guide: Testing JSON Web Tokens](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens)
  
