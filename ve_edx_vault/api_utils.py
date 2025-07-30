"""
API utils to get OAuth token and user access token from edu vault.
"""

import json
import logging
from typing import Dict, Any

from django.core.exceptions import ObjectDoesNotExist
from oauth2_provider.models import Application
from requests.exceptions import HTTPError, RequestException
from edx_rest_api_client.client import OAuthAPIClient

import requests
from urllib.parse import urljoin

log = logging.getLogger(__name__)

# Constants
EDU_VAULT_USER_TOKEN_CLIENT_NAME = "edu-vault-user-token-client"


class EduVaultError(Exception):
    """Base exception for edu vault operations."""
    pass


class OAuthClientNotFoundError(EduVaultError):
    """Raised when OAuth client is not found in the database."""
    pass


class OAuthTokenError(EduVaultError):
    """Raised when OAuth token request fails."""
    pass


class UserTokenError(EduVaultError):
    """Raised when user token request fails."""
    pass


def create_edx_api_client(
    api_client_id: str,
    api_client_secret: str,
    root_url: str
) -> OAuthAPIClient:
    """
    Create an API client for making edX API requests.

    Args:
        api_client_id: OAuth client ID for authentication
        api_client_secret: OAuth client secret for authentication
        root_url: Base URL for the edu vault instance (e.g., "http://localhost:8000")

    Returns:
        Configured OAuth API client for making authenticated requests

    Raises:
        ValueError: If any required parameter is empty or None
    """
    if not all([api_client_id, api_client_secret, root_url]):
        raise ValueError("All parameters (api_client_id, api_client_secret, root_url) are required")

    log.debug("Creating edX API client for root_url: %s", root_url)
    return OAuthAPIClient(root_url, api_client_id, api_client_secret)


def get_oauth_token(root_url: str) -> str:
    """
    Get OAuth token from /api/v1/oauth/token/ endpoint.

    Args:
        root_url: Base URL for the edu vault instance (e.g., "http://localhost:8000")

    Returns:
        OAuth access token

    Raises:
        ValueError: If root_url is empty or None
        OAuthClientNotFoundError: If OAuth client is not found
        OAuthTokenError: If token request fails
    """
    if not root_url:
        raise ValueError("root_url is required")

    log.info("Requesting OAuth token from %s", root_url)

    try:
        oauth_client = Application.objects.get(name=EDU_VAULT_USER_TOKEN_CLIENT_NAME)
        log.debug("Found OAuth client: %s", EDU_VAULT_USER_TOKEN_CLIENT_NAME)
    except ObjectDoesNotExist as exc:
        log.error("OAuth client not found: %s", EDU_VAULT_USER_TOKEN_CLIENT_NAME)
        raise OAuthClientNotFoundError(
            f"OAuth client '{EDU_VAULT_USER_TOKEN_CLIENT_NAME}' not found"
        ) from exc

    client = create_edx_api_client(
        oauth_client.client_id,
        oauth_client.client_secret,
        root_url
    )

    token_url = urljoin(root_url, '/api/v1/oauth/token/')
    oauth_data = {
        'grant_type': 'client_credentials',
        'client_id': oauth_client.client_id,
        'client_secret': oauth_client.client_secret,
    }

    try:
        response = client.post(token_url, data=oauth_data)
        response.raise_for_status()

        token_data = response.json()
        oauth_token = token_data.get('access_token')

        if not oauth_token:
            raise OAuthTokenError("No access_token in response")

        log.info("Successfully obtained OAuth token")
        return oauth_token

    except HTTPError as exc:
        log.error(
            "HTTP error while getting OAuth token -- status: %s, content: %s",
            exc.response.status_code,
            exc.response.content
        )
        try:
            error_data = exc.response.json()
            error_msg = error_data.get('error_description', str(exc))
        except (json.JSONDecodeError, AttributeError):
            error_msg = str(exc)

        raise OAuthTokenError(f"Failed to get OAuth token: {error_msg}") from exc

    except RequestException as exc:
        log.error("Request error while getting OAuth token: %s", str(exc))
        raise OAuthTokenError(f"Network error while getting OAuth token: {exc}") from exc

    except Exception as exc:
        log.error("Unexpected error while getting OAuth token: %s", str(exc))
        raise OAuthTokenError(f"Unexpected error while getting OAuth token: {exc}") from exc


def get_user_access_token(username: str, root_url: str) -> Dict[str, Any]:
    """
    Get user access token from /api/v1/auth/edx_user/token using OAuth token.

    This function first obtains an OAuth token, then uses it to request a user-specific
    access token from the edu vault API.

    Args:
        username: Username for which to get the access token
        root_url: Base URL for the edX instance (e.g., "http://localhost:8000")

    Returns:
        User token data dictionary

    Raises:
        ValueError: If username or root_url is empty or None
        OAuthClientNotFoundError: If OAuth client is not found
        OAuthTokenError: If OAuth token request fails
        UserTokenError: If user token request fails
    """
    if not username:
        raise ValueError("username is required")
    if not root_url:
        raise ValueError("root_url is required")

    log.info("Requesting user access token for username: %s", username)

    oauth_token = get_oauth_token(root_url)

    headers = {
        'Authorization': f'Bearer {oauth_token}',
        'Content-Type': 'application/json'
    }
    payload = {"username": username}
    user_token_url = f"{root_url}/api/v1/auth/edx_user/token"

    log.debug("Making user token request to: %s", user_token_url)

    try:
        response = requests.post(user_token_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()

        user_token = response.json()
        log.info("Successfully obtained user access token for username: %s", username)
        return user_token

    except HTTPError as exc:
        log.error(
            "HTTP error while getting user access token -- username: %s, status: %s, content: %s",
            username,
            exc.response.status_code,
            exc.response.content
        )
        try:
            error_data = exc.response.json()
            error_msg = error_data.get('error_description', str(exc))
        except (json.JSONDecodeError, AttributeError):
            error_msg = str(exc)

        raise UserTokenError(
            f"Failed to get user access token for '{username}': {error_msg}"
        ) from exc

    except RequestException as exc:
        log.error(
            "Request error while getting user access token for username %s: %s",
            username,
            str(exc)
        )
        raise UserTokenError(
            f"Network error while getting user access token for '{username}': {exc}"
        ) from exc

    except Exception as exc:
        log.error(
            "Unexpected error while getting user access token for username %s: %s",
            username,
            str(exc)
        )
        raise UserTokenError(
            f"Unexpected error while getting user access token for '{username}': {exc}"
        ) from exc

