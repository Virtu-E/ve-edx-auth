"""
Defines URL routes for the API.
"""

from django.urls import  include


try:
    from django.conf.urls import url as path
except ImportError:
    from django.urls import re_path as path


# Import views
from .. import api


app_name = 've_edx_vault'

urlpatterns = [
    path('user/token/', api.get_user_token_proxy, name='get_user_token_proxy'),

]
