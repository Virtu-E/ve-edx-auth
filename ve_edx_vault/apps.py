"""
App Configuration for Ve-Edx-Auth app
"""

from django.apps import AppConfig
from edx_django_utils.plugins.constants import (PluginContexts, PluginSettings,
                                                PluginURLs)
from openedx.core.djangoapps.plugins.constants import ProjectType, SettingsType


class EdxAuthApp(AppConfig):
    name = "ve_edx_vault"
    verbose_name = "Virtu Educate Edu Vault Authentication App"

    plugin_app = {
        PluginURLs.CONFIG: {
            ProjectType.LMS: {
                PluginURLs.NAMESPACE: "ve_edx_vault",
                PluginURLs.REGEX: r"^api/v1/vault/",
                PluginURLs.RELATIVE_PATH: "urls.lms",
            },
        },
        PluginSettings.CONFIG: {
            ProjectType.LMS: {
                SettingsType.COMMON: {PluginSettings.RELATIVE_PATH: "settings.common"},
            }
        },
    }

    def ready(self):
        pass
