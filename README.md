# VE-EDX-Auth

An Open edX Django app that provides a proxy endpoint to get user access tokens from Edu Vault backend using Open edX's built-in OAuth infrastructure.

## Description

This app enables secure token exchange by leveraging Open edX's existing OAuth system to authenticate with Edu Vault and retrieve user-specific access tokens. It acts as a proxy between your frontend applications and the Edu Vault authentication API.

## Features

- **OAuth Integration**: Uses Open edX's built-in OAuth2 provider for secure authentication
- **Token Proxy**: Provides a clean API endpoint to get user tokens from Edu Vault
- **Type Safety**: Full type hints and comprehensive error handling
- **Logging**: Structured logging for monitoring and debugging
- **Simple Setup**: Minimal configuration required

## Installation

1. Install the package:
   ```bash
   pip install ve-edx-auth
   ```



## Configuration

### 1. Create OAuth Application

Create an OAuth application in your Open edX admin panel:

1. Go to `/admin/oauth2_provider/application/`
2. Click "Add Application"
3. Set the following:
   - **Name**: `edx-user-token-client`
   - **Client type**: `Confidential`
   - **Authorization grant type**: `Client credentials`
4. Save the application

### 2. Environment Setup

The app uses the requesting URL dynamically, so no additional URL configuration is needed.

## Usage

### API Endpoint

The app provides a single proxy endpoint:

```
POST api/v1/vault/user/token/'
```

### Request Format

```javascript
fetch('api/v1/vault/user/token/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCookie('csrftoken')  // Django CSRF token
    },
    body: JSON.stringify({
        'username': 'your_username',
        'root-url' : "https://vault.virtueducate.edly.io/"
    })
})
.then(response => response.json())
.then(data => console.log(data))
.catch(error => console.error(error));
```

### Response Format

**Success Response:**
```json
{
    "token": "user_access_token_here",
    "expires_at": "2024-01-01T12:00:00Z",
    // ... other token data from Edu Vault
}
```

**Error Response:**
```json
{
    "error": "Username is required"
}
```
