"""
API utils to get OAuth token and user access token from edu vault.
"""

import json
import logging
from typing import Tuple, Dict, Any, Optional

from django.core.exceptions import ObjectDoesNotExist
from oauth2_provider.models import Application
from requests.exceptions import HTTPError
from openedx.core.lib.api.clients import OAuthAPIClient
import requests

log = logging.getLogger(__name__)

# Hard-coded values
EDU_VAULT_USER_TOKEN_CLIENT_NAME = "edu-vault-user-token-client"


def create_edx_api_client(
        api_client_id: str,
        api_client_secret: str,
        root_url: str
) -> OAuthAPIClient:
    """
    Returns an API client which can be used to make edX API requests.

    Args:
        api_client_id (str): OAuth client ID for authentication
        api_client_secret (str): OAuth client secret for authentication
        root_url (str): Base URL for the edX instance (e.g., "http://localhost:8000")

    Returns:
        OAuthAPIClient: Configured OAuth API client for making authenticated requests
    """
    log.debug("Creating edX API client for root_url: %s", root_url)
    return OAuthAPIClient(root_url, api_client_id, api_client_secret)


def get_oauth_token(*, root_url: str) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Get OAuth token from /api/v1/oauth/token/ endpoint.

    Args:
        root_url (str): Base URL for the edX instance (e.g., "http://localhost:8000")

    Returns:
        Tuple[Dict[str, Any], Optional[str]]: A tuple containing:
            - error_response (Dict): Error details if request failed, empty dict if successful
            - oauth_token (Optional[str]): OAuth access token if successful, None if failed
    """
    log.info("Requesting OAuth token from %s", root_url)
    error_response: Dict[str, Any] = {"message": "no edu-vault-user-token-client client found"}
    oauth_token: Optional[str] = None

    try:
        oauth_client = Application.objects.get(name=EDU_VAULT_USER_TOKEN_CLIENT_NAME)
        log.debug("Found OAuth client: %s", EDU_VAULT_USER_TOKEN_CLIENT_NAME)
    except ObjectDoesNotExist:
        log.error("OAuth client not found: %s", EDU_VAULT_USER_TOKEN_CLIENT_NAME)
        return error_response, oauth_token

    client = create_edx_api_client(
        oauth_client.client_id,
        oauth_client.client_secret,
        root_url
    )

    oauth_url = "/api/v1/oauth/token/"

    try:
        response = client.post(oauth_url)
        response.raise_for_status()

        if response.ok:
            token_data = response.json()
            oauth_token = token_data.get('access_token')
            log.info("Successfully obtained OAuth token")
        else:
            error_response = json.loads(response.text)
            log.error("Failed to get OAuth token -- status: %s, response: %s",
                      response.status_code, response.text)

    except HTTPError as ex:
        log.error("HTTP error while getting OAuth token -- status: %s, content: %s",
                  ex.response.status_code, ex.response.content)
        error_response = json.loads(ex.response.content)
    except Exception as ex:
        log.error("Unexpected error while getting OAuth token: %s", str(ex))
        error_response = {"error": "Unexpected error occurred"}

    return error_response, oauth_token


def get_user_access_token(
        *,
        username: str,
        root_url: str
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    Get user access token from /api/v1/auth/edx_user/token using OAuth token.

    This function first obtains an OAuth token, then uses it to request a user-specific
    access token from the edu vault API.

    Args:
        username (str): Username for which to get the access token
        root_url (str): Base URL for the edX instance (e.g., "http://localhost:8000")

    Returns:
        Tuple[Dict[str, Any], Optional[Dict[str, Any]]]: A tuple containing:
            - error_response (Dict): Error details if request failed, empty dict if successful
            - user_token (Optional[Dict]): User token data if successful, None if failed
    """
    log.info("Requesting user access token for username: %s", username)
    error_response: Dict[str, Any] = {}
    user_token: Optional[Dict[str, Any]] = None

    # First get OAuth token
    oauth_error, oauth_token = get_oauth_token(root_url=root_url)
    if oauth_error or not oauth_token:
        log.error("Failed to obtain OAuth token, cannot proceed with user token request")
        return oauth_error, user_token

    # Prepare headers
    headers = {
        'Authorization': f'Bearer {oauth_token}',
        'Content-Type': 'application/json'
    }

    # Prepare payload
    payload = {"username": username}

    # Full URL
    user_token_url = f"{root_url}/api/v1/auth/edx_user/token"
    log.debug("Making user token request to: %s", user_token_url)

    try:
        response = requests.post(user_token_url, headers=headers, json=payload)
        response.raise_for_status()

        if response.ok:
            user_token = response.json()
            log.info("Successfully obtained user access token for username: %s", username)
        else:
            error_response = json.loads(response.text)
            log.error("Failed to get user access token -- username: %s, status: %s, response: %s",
                      username, response.status_code, response.text)

    except HTTPError as ex:
        log.error("HTTP error while getting user access token -- username: %s, status: %s, content: %s",
                  username, ex.response.status_code, ex.response.content)
        error_response = json.loads(ex.response.content)
    except Exception as ex:
        log.error("Unexpected error while getting user access token for username %s: %s",
                  username, str(ex))
        error_response = {"error": "Unexpected error occurred"}

    return error_response, user_token