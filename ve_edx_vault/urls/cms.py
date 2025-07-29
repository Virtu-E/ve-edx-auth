"""
Defines URL routes for the API.
"""

from django.urls import  include


try:
    from django.conf.urls import url as path
except ImportError:
    from django.urls import re_path as path


# Import views
from ve_edx_vault.views import api

app_name = 've_edx_vault'

urlpatterns = [
    path(
        r'^user/token?$',
        api.create_full_course,
        name="user-access-token",
    ),

]
