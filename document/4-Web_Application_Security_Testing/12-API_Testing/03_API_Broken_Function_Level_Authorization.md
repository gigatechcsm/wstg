# API Broken Function Level Authorization

|ID          |
|------------|
|WSTG-APIT-03|

## Summary

Broken Function Level Authorization (BFLA) occurs when an API improperly enforces restrictions on users accessing certain functions or operations. This vulnerability allows attackers to invoke sensitive functions they are not authorized to execute, such as administrative functions or other high-privilege operations.

BFLA commonly arises when APIs expose multiple endpoints that serve different user roles (e.g., user vs. admin) but fail to restrict access to these functions based on the user's authorization level.

Exploiting BFLA can lead to serious consequences such as **privilege escalation**, unauthorized access to sensitive functions (e.g., administrative operations), or exposure of critical functionalities that should only be accessible to specific user roles.

## Test Objectives

- The goal of this test is to determine if the API enforces **role- or privilege-based access control** to restrict users from accessing or executing functions they are not authorized to use. This ensures that function-level security boundaries are properly enforced.

## How to Test

### Identify Function-Level Endpoints

Review API documentation (e.g. OpenAPI specification) or inspect API traffic using an interception proxy (e.g., **Burp Suite**, **Postman**, **OWASP ZAP**) to identify different function-level endpoints. These might include:
  
- **Administrative functions** (e.g., `/api/admin/deleteUser`, `/api/admin/getAllUsers`)

- **Role-based operations** (e.g., `/api/admin/promoteUser`, `/api/user/createOrder`)

- **Critical functions** for users (e.g., `/api/user/withdrawFunds`)

Focus on **functionality differences** between different user roles (e.g., regular user, admin, guest) and endpoints that offer more sensitive capabilities.

### Manipulate Role-Based Access Controls

Try to access or perform sensitive operations exposed in API endpoints that should be restricted based on user roles.

Log in as a lower-privilege user (e.g., a regular user or guest) and send requests to endpoints that perform sensitive actions reserved for higher-privilege roles (e.g., admin actions).

Example:
As a **regular user**, send a request to the following admin endpoint:

    ```
    POST /api/admin/deleteUser
    Authorization: Bearer <regular_user_token>
    {
      "userId": "12345"
    }
    ```
    
### Test Function-Level Access with Different HTTP Methods

Test various **HTTP methods** for BFLA vulnerabilities:

- **GET**: Attempt to access information available only to high-privilege users (e.g., admins).

Example: `GET /api/admin/getAllUsers`

- **POST/PUT/PATCH**: Attempt to modify or create sensitive resources (e.g., changing user roles, creating or deleting system-critical data).

Example: `POST /api/admin/promoteUser { "userId": "12345", "newRole": "admin" }`

- **DELETE**: Attempt to delete sensitive resources, such as removing user accounts or data.

Example: `DELETE /api/admin/deleteUser/12345`

### Test for BFLA in GraphQL APIs

In **GraphQL APIs**, test if a user can invoke functions restricted to higher-privilege roles by modifying GraphQL queries.

Example:

    ```graphql
    mutation {
      deleteUser(id: "12345") {
        success
      }
    }
    ```

## Indicators of BFLA

- **Successful exploitation**: If modifying an object ID in the request returns data or allows actions on objects that belong to other users, the API is vulnerable to BOLA.

- **Error responses**: Properly secured APIs in general would return `403 Forbidden` or `401 Unauthorized` for unauthorized object access. A `200 OK` response for another user's object indicates BOLA.

- **Inconsistent responses**: If some endpoints enforce authorization and others do not, it points to incomplete or inconsistent security controls.

## Remediations

To prevent BFLA vulnerabilities, implement the following mitigations:

- **Enforce Role-Based Access Control (RBAC)**: Ensure that the API checks user roles and permissions at the **function level** before allowing access to certain operations. Only authorized roles should be allowed to invoke sensitive functions.
- **Least Privilege Principle**: Apply the principle of least privilege by ensuring that users can only access the minimum set of functions they need for their role.
- **Implement Authorization Middleware**: Use authorization middleware that checks the user's role and permissions for each function before processing the request.
- **Centralized Access Control Logic**: Use centralized access control logic to ensure consistency across all API endpoints. This avoids gaps where some functions may lack proper access checks.

## Tools

- **ZAP**: Automated scanners or manual proxy tools can help test object references in API requests.
- **Burp Suite**: Use the **Repeater** or **Intruder** tools to manipulate object IDs and send multiple requests to test access control.
- **Postman**: Send requests with altered object IDs and observe the responses.
- **Fuzzing Tools**: Use fuzzers to brute-force object IDs and check for unauthorized access.

## References

- [OWASP API Security Top 10: BFLA](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [OWASP Testing Guide: Testing for Business Logic Vulnerabilities](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation)
