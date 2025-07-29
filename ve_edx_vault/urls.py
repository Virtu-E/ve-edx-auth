from django.urls import path
from . import api

urlpatterns = [
    path('user/token/', api.get_user_token_proxy, name='get_user_token_proxy'),
]