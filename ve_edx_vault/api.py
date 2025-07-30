import json
import logging

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .api_utils import (EduVaultError, OAuthClientNotFoundError,
                        OAuthTokenError, UserTokenError, get_user_access_token)
from .models import EdxUserDetails

log = logging.getLogger(__name__)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def get_user_token_proxy(request):
    """
    Proxy endpoint to get user access token from edu vault.

    Expected JSON payload:
    {
        "username": "user123",
        "root_url": "http://localhost:8000"
    }

    Returns:
        JsonResponse: User token data or error response
    """
    try:
        log.info("Request content type: %s", request.content_type)

        username = request.user.username
        root_url = getattr(settings, "EDU_VAULT_ROOT_URL", None)

        if not username:
            return JsonResponse({"error": "Username is required"}, status=400)

        if not root_url:
            return JsonResponse(
                {
                    "error": "EDU_VAULT_ROOT_URL is required, please configure it in django settings"
                },
                status=400,
            )

        user_details: EdxUserDetails = {
            "username": username,
            "user_id": request.user.id,
            "full_name": request.user.get_full_name(),
            "email": request.user.email,
            "first_name": request.user.first_name,
            "last_name": request.user.last_name,
        }

        user_token = get_user_access_token(
            username=username, root_url=root_url, user_details=user_details
        )

        log.info("Successfully retrieved user token for username: %s", username)
        return JsonResponse(user_token)

    except ValueError as e:
        log.warning("Validation error: %s", str(e))
        return JsonResponse({"error": str(e)}, status=400)

    except OAuthClientNotFoundError as e:
        log.error("OAuth client not found: %s", str(e))
        return JsonResponse(
            {
                "error": "OAuth client configuration error. Please contact administrator."
            },
            status=500,
        )

    except OAuthTokenError as e:
        log.error("OAuth token error: %s", str(e))
        return JsonResponse(
            {"error": "Failed to obtain OAuth token. Please try again later."},
            status=502,
        )  # Bad Gateway - upstream service issue

    except UserTokenError as e:
        log.error(
            "User token error for username %s: %s",
            username if "username" in locals() else "unknown",
            str(e),
        )
        return JsonResponse(
            {
                "error": f"Failed to get user access token. Please verify the username and try again."
            },
            status=400,
        )

    except EduVaultError as e:
        log.error("Edu vault error: %s", str(e))
        return JsonResponse(
            {"error": "Service temporarily unavailable. Please try again later."},
            status=503,
        )

    except Exception as e:
        log.exception("Unexpected error in get_user_token_proxy: %s", str(e))
        return JsonResponse(
            {"error": "An unexpected error occurred. Please try again later."},
            status=500,
        )
