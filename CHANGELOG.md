# Changelog

All notable changes to VE-EDX-Auth will be documented in this file.

## [Unreleased]

## [2.0.1] - 2025-07-30

### Removed
- Request body logging for improved security and privacy
- JSON payload parsing and validation (no longer accepts request body)
- Empty request body validation checks
- JSON decode error handling

### Changed
- Simplified endpoint to use only authenticated user data
- Reduced logging verbosity by removing request body details

### Security
- Enhanced privacy by eliminating request body logging
- Removed potential data exposure through request logs

## [2.0.0] - 2025-07-30

### Security
- **CRITICAL**: Fixed URL injection vulnerability - user-provided URLs no longer accepted
- Replace hardcoded root URL with Django settings configuration

### Added
- `EDU_VAULT_ROOT_URL` Django setting for secure URL configuration
- Enhanced error handling with specific exception types
- Comprehensive documentation and setup guide

### Changed
- **BREAKING**: Requires `EDU_VAULT_ROOT_URL` in Django settings
- Improved API error responses and validation

## [1.x.x] - Previous Versions

- Initial implementation of OAuth token proxy functionality
- Basic edX platform integration
- Core authentication flow establishment

## Security Notice

v2.0.1 improves security by removing request body logging and simplifying the endpoint.
v2.0.0 fixes a critical URL injection vulnerability. Immediate upgrade recommended.

**Migration**: Add `EDU_VAULT_ROOT_URL = 'https://your-domain.com'` to Django settings.
