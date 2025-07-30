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

## Multi-Service Authentication Architecture

This app is part of a larger multi-service authentication system that integrates:
- **VE-EDX-Auth**: This Django app (token proxy)
- **edX Platform**: Provides user authentication via username/password
- **Dashboard Frontend**: Main application interface
- **EduVault Backend**: Educational content and user data API

## System Architecture

```mermaid
graph TB
    User[👤 User] --> Dashboard[🖥️ Dashboard Frontend]
    
    Dashboard --> AuthCheck{Has Valid Tokens?}
    AuthCheck -->|No| Redirect[↩️ Redirect to Auth]
    AuthCheck -->|Yes| Protected[🛡️ Protected Routes]
    
    Redirect --> Auth[🔐 VE-EDX-Auth App]
    Auth --> EdXLogin[🎓 edX Username/Password Login]
    EdXLogin -->|Success| Callback[📞 Auth Callback Handler]
    
    Callback --> TokenProxy[🔄 VE-EDX-Auth Token Proxy]
    TokenProxy --> EduVault[📚 EduVault Backend]
    EduVault -->|User Token| TokenProxy
    TokenProxy -->|Encrypted Token| Callback
    
    Callback --> StoreTokens[🔐 Store Encrypted Tokens in Cookies]
    StoreTokens --> Protected
    
    Protected --> EdXAPI[📡 edX API Calls]
    Protected --> VaultAPI[📡 EduVault API Calls]
    
    subgraph "Backend Security (All APIs)"
        RateLimit[⚡ Rate Limiting]
        IPCheck[🛡️ IP Whitelist Check]
        RBAC[🔑 Role-Based Access Control]
        AAA[🔒 Authentication, Authorization, Accounting]
    end
    
    EdXAPI --> RateLimit
    VaultAPI --> RateLimit
    RateLimit --> IPCheck
    IPCheck --> RBAC
    RBAC --> AAA
```

## Authentication Flow

### 1. Initial User Login

When a user needs to authenticate:

```mermaid
sequenceDiagram
    participant U as User
    participant D as Dashboard
    participant VA as VE-EDX-Auth App
    participant EDX as edX Platform
    participant IV as Input Validator
    
    U->>D: Access Dashboard
    D->>D: Check Token Cookies
    
    alt No Valid Tokens
        D->>VA: Redirect to /auth/login
        VA->>VA: Show Login Form
        U->>VA: Enter Username & Password
        
        VA->>IV: Validate Login Input
        IV-->>VA: Validation Result
        
        alt Input Invalid
            VA-->>U: Show Validation Errors
        else Input Valid
            VA->>EDX: Authenticate (username/password)
            EDX-->>VA: Authentication Result
            
            alt Login Success
                VA->>VA: Store edX Session
                VA->>D: Redirect to /auth/callback
            else Login Failed
                VA-->>U: Show Login Error
            end
        end
    end
```

### 2. Token Exchange Process

After successful edX authentication, the token proxy handles secure token exchange:

```mermaid
sequenceDiagram
    participant D as Dashboard
    participant CB as Callback Handler
    participant VA as VE-EDX-Auth Proxy
    participant EV as EduVault Backend
    participant SEC as Backend Security
    
    D->>CB: Handle /auth/callback
    CB->>VA: Request EduVault Token
    
    VA->>SEC: Security Checks
    SEC->>SEC: Rate Limiting Check
    SEC->>SEC: IP Whitelist Validation
    SEC-->>VA: Security Validation Result
    
    alt Security Checks Failed
        VA-->>CB: Security Error
        CB->>D: Redirect to Login with Error
    else Security Checks Passed
        VA->>EV: Server-to-Server OAuth Request
        EV->>SEC: Additional AAA + RBAC Checks
        SEC-->>EV: Authorization Result
        
        alt User Authorized
            EV-->>VA: User Token + Expiry + Permissions
            VA-->>CB: Return Encrypted Token Data
            CB->>CB: Store Encrypted Token in HttpOnly Cookie
            CB->>D: Navigate to Protected Route
        else User Not Authorized
            EV-->>VA: Access Denied
            VA-->>CB: Authorization Error
            CB->>D: Show Access Denied Message
        end
    end
```

## Security Implementation

### Backend Security (Django Settings)

All security checks happen at the Django backend level when API calls are made:

```python
# settings.py - Security Configuration
ALLOWED_HOSTS = ["localhost", "127.0.0.1", ".virtueducate.com"]

# Rate Limiting (applied to all API endpoints)
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'

# Secure Cookies
SECURE_COOKIE_HTTPONLY = True
SECURE_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SAMESITE = 'Strict'

etc
```

### 1. Rate Limiting

Applied automatically to all backend API endpoints:

```python
# Applied to VE-EDX-Auth endpoints
@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def token_proxy_view(request):
    """Rate limited token proxy endpoint"""
    pass

# Applied to EduVault API endpoints  
@ratelimit(key='user', rate='100/h', method='GET', block=True)
def get_user_data(request):
    """Rate limited data access"""
    pass

# Applied to edX API endpoints
@ratelimit(key='ip', rate='50/m', method='ALL', block=True)
def edx_api_endpoint(request):
    """Rate limited edX API access"""
    pass
```

### 2. IP Whitelisting

Handled at Django application level via `ALLOWED_HOSTS`:

```python
# Only requests from these domains/IPs are accepted
ALLOWED_HOSTS = [
    "localhost",           # Development
    "127.0.0.1",          # Local testing  
    ".virtueducate.com"   # Production domain and subdomains
]


```



## Token Storage and Management

### Encrypted Cookie Storage

Frontend stores tokens securely using encrypted HTTP-only cookies:

```typescript
// Frontend encrypted cookie management
class SecureTokenManager {
    private readonly ENCRYPTION_KEY = process.env.REACT_APP_TOKEN_KEY!
    
    storeToken(token: string, expiry: Date): void {
        // Encrypt token before storage
        const encrypted = CryptoJS.AES.encrypt(token, this.ENCRYPTION_KEY).toString()
        
        // Store in secure HTTP-only cookie
        document.cookie = [
            `auth_token=${encrypted}`,
            `expires=${expiry.toUTCString()}`,
            'HttpOnly',
            'Secure', 
            'SameSite=Strict',
            'Path=/'
        ].join('; ')
    }
    
    getToken(): string | null {
        const encrypted = this.getCookieValue('auth_token')
        if (!encrypted) return null
        
        try {
            const decrypted = CryptoJS.AES.decrypt(encrypted, this.ENCRYPTION_KEY)
            return decrypted.toString(CryptoJS.enc.Utf8)
        } catch {
            this.clearToken()
            return null
        }
    }
    
    private getCookieValue(name: string): string | null {
        const value = `; ${document.cookie}`
        const parts = value.split(`; ${name}=`)
        return parts.length === 2 ? parts.pop()?.split(';').shift() || null : null
    }
}
```

## API Call Security Flow

Every API call goes through comprehensive backend security validation:

```mermaid
sequenceDiagram
    participant F as Frontend
    participant BE as Backend API
    participant RL as Rate Limiter  
    participant IP as IP Validator
    participant AAA as AAA + RBAC
    participant DB as Database
    
    F->>BE: API Request with Token Cookie
    BE->>RL: Check Rate Limits
    
    alt Rate Limit Exceeded
        RL-->>F: 429 Too Many Requests
    else Rate Limit OK
        RL->>IP: Validate Request IP
        
        alt IP Not Allowed
            IP-->>F: 403 IP Forbidden
        else IP Allowed
            IP->>AAA: Authenticate & Authorize User
            AAA->>AAA: Check User Permissions for Resource
            
            alt Permission Denied
                AAA-->>F: 403 Access Denied
            else Permission Granted
                AAA->>DB: Execute Database Query
                DB-->>AAA: Return Data
                AAA->>AAA: Log Access for Accounting
                AAA-->>F: 200 Success with Data
            end
        end
    end
```

## Installation and Setup

### 1. Install VE-EDX-Auth App

```bash
# Clone the repository
git clone https://github.com/your-org/VE-EDX-Auth.git

# Install in your edX installation
pip install -e ./VE-EDX-Auth
```

### 2. Add to edX Configuration

```python

# Configure EduVault backend URL
EDUVAULT_API_URL = 'https://vault.virtueducate.com/api'
```



## Security Features Summary

### ✅ **Implemented Security Measures**

1. **Rate Limiting**: All API endpoints protected against abuse
2. **IP Whitelisting**: Request filtering at Django `ALLOWED_HOSTS` level  
3. **Encrypted Token Storage**: AES-encrypted HTTP-only cookies
4. **Input Validation**: Comprehensive validation for login credentials
5. **AAA + RBAC**: Authentication, Authorization, Accounting with role-based permissions
6. **Server-Side Security**: All security checks happen in backend, no frontend bypass possible

### 🔒 **Security Architecture Benefits**

- **Defense in Depth**: Multiple security layers prevent single point of failure
- **Zero Frontend Trust**: All security validation occurs server-side
- **Comprehensive Logging**: Full audit trail for compliance and monitoring
- **Token Security**: Encrypted storage prevents XSS-based token theft
- **Access Control**: Fine-grained permissions for resource access



