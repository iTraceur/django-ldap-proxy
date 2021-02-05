"""
Settings used by django-python3.
"""

from django.conf import settings


class LazySetting(object):
    """
    A proxy to a named Django setting.
    """

    def __init__(self, name, default=None):
        self.name = name
        self.default = default

    def __get__(self, obj, cls):
        if obj is None:
            return self
        return getattr(obj._settings, self.name, self.default)


class LazySettings(object):
    """
    A proxy to ldap-specific django settings.

    Settings are resolved at runtime, allowing tests
    to change settings at runtime.
    """

    LDAP_DOMAIN_SLICE = settings.LDAP_DOMAIN_SLICE if hasattr(settings, 'LDAP_DOMAIN_SLICE') else ('example', 'com')

    def __init__(self, settings):
        self._settings = settings

    LDAP_AUTH_URL = LazySetting(
        name="LDAP_AUTH_URL",
        default="ldap://localhost:389",
    )

    LDAP_AUTH_USE_TLS = LazySetting(
        name="LDAP_AUTH_USE_TLS",
        default=False,
    )

    LDAP_AUTH_SEARCH_BASE = LazySetting(
        name="LDAP_AUTH_SEARCH_BASE",
        default=f"ou=people,dc={LDAP_DOMAIN_SLICE[0]},dc={LDAP_DOMAIN_SLICE[1]}",
    )

    LDAP_POLICY_SEARCH_BASE = LazySetting(
        name="LDAP_POLICY_SEARCH_BASE",
        default=f"ou=policies,dc={LDAP_DOMAIN_SLICE[0]},dc={LDAP_DOMAIN_SLICE[1]}",
    )

    LDAP_AUTH_OBJECT_CLASS = LazySetting(
        name="LDAP_AUTH_OBJECT_CLASS",
        default="inetOrgPerson",
    )

    LDAP_AUTH_USER_FIELDS = LazySetting(
        name="LDAP_AUTH_USER_FIELDS",
        default={
            "username": "uid",
            "first_name": "givenName",
            "last_name": "sn",
            "email": "mail",
        },
    )

    LDAP_AUTH_USER_LOOKUP_FIELDS = LazySetting(
        name="LDAP_AUTH_USER_LOOKUP_FIELDS",
        default=(
            "username",
        ),
    )

    LDAP_AUTH_CLEAN_USER_DATA = LazySetting(
        name="LDAP_AUTH_CLEAN_USER_DATA",
        default="django_ldap_proxy.utils.clean_user_data",
    )

    LDAP_AUTH_FORMAT_SEARCH_FILTERS = LazySetting(
        name="LDAP_AUTH_FORMAT_SEARCH_FILTERS",
        default="django_ldap_proxy.utils.format_search_filters",
    )

    LDAP_AUTH_SYNC_USER_RELATIONS = LazySetting(
        name="LDAP_AUTH_SYNC_USER_RELATIONS",
        default="django_ldap_proxy.utils.sync_user_relations",
    )

    LDAP_AUTH_FORMAT_USERNAME = LazySetting(
        name="LDAP_AUTH_FORMAT_USERNAME",
        default="django_ldap_proxy.utils.format_username_openldap",
    )

    LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN = LazySetting(
        name="LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN",
        default=None,
    )

    LDAP_AUTH_TEST_USER_USERNAME = LazySetting(
        name="LDAP_AUTH_TEST_USER_USERNAME",
        default="",
    )

    LDAP_AUTH_TEST_USER_PASSWORD = LazySetting(
        name="LDAP_AUTH_TEST_USER_PASSWORD",
        default="",
    )

    LDAP_AUTH_CONNECTION_USERNAME = LazySetting(
        name="LDAP_AUTH_CONNECTION_USERNAME",
        default=None,
    )

    LDAP_AUTH_CONNECTION_PASSWORD = LazySetting(
        name="LDAP_AUTH_CONNECTION_PASSWORD",
        default=None,
    )

    LDAP_DEFAULT_PASSWORD = LazySetting(
        name="LDAP_DEFAULT_PASSWORD",
        default="",
    )

    LDAP_AUTH_CONNECT_TIMEOUT = LazySetting(
        name="LDAP_AUTH_CONNECT_TIMEOUT",
        default=5
    )

    LDAP_AUTH_RECEIVE_TIMEOUT = LazySetting(
        name="LDAP_AUTH_RECEIVE_TIMEOUT",
        default=5
    )

    LDAP_PPOLICY_ENABLED = LazySetting(
        name="LDAP_PPOLICY_ENABLED",
        default=False
    )

    RAISE_EXCEPTION = LazySetting(
        name="RAISE_EXCEPTION",
        default=True
    )


config = LazySettings(settings)
