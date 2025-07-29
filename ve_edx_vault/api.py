from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
import json

from .api_utils import get_user_access_token


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def get_user_token_proxy(request):
    """
    Proxy endpoint to get user access token from edu vault
    """
    try:
        # Get the requesting root URL
        root_url = f"{request.scheme}://{request.get_host()}"
        # This will give you something like: "http://localhost:8000" or "https://yourdomain.com"

        request_data = json.loads(request.body)
        username = request_data.get('username')

        if not username:
            return JsonResponse({
                'error': 'Username is required'
            }, status=400)


        error, user_token = get_user_access_token(username = username, root_url=root_url )

        if user_token:
            return JsonResponse(user_token)
        else:
            return JsonResponse({'error': error}, status=400)

    except json.JSONDecodeError:
        return JsonResponse({
            'error': 'Invalid JSON in request body'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)