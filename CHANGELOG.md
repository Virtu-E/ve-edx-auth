# Changelog

All notable changes to VE-EDX-Auth will be documented in this file.

## [Unreleased]

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

v2.0.0 fixes a critical URL injection vulnerability. Immediate upgrade recommended.

**Migration**: Add `EDU_VAULT_ROOT_URL = 'https://your-domain.com'` to Django settings.
