"""
Django authentication backend.
"""

from django.contrib.auth.backends import ModelBackend

from .conf import config
from .ldap import connection
from .utils import get_or_create_user


def authenticate(*args, **kwargs):
    """
    Authenticates with the LDAP server, and returns
    the corresponding Django user instance.

    The user identifier should be keyword arguments matching the fields
    in config.LDAP_AUTH_USER_LOOKUP_FIELDS, plus a `password` argument.
    """
    password = kwargs.pop("password", None)
    # Check that this is valid login data.
    if not password or frozenset(kwargs.keys()) != frozenset(config.LDAP_AUTH_USER_LOOKUP_FIELDS):
        return None

    # Connect to LDAP.
    with connection(password=password, **kwargs) as c:
        if not c:
            return

        try:
            username = kwargs.get('username')
            user_data = c.get_user(**kwargs)
            if not user_data:
                return

            user = get_or_create_user(user_data)
            if not user:
                return

            user.password_validity_period = c.get_pwd_validity_period(username)
            if not user.required_change_password:
                user.required_change_password = user.is_password_expired()
            user.save()
            return user
        except:
            pass


class LDAPBackend(ModelBackend):
    """
    An authentication backend that delegates to an LDAP
    server.

    User models authenticated with LDAP are created on
    the fly, and syncronised with the LDAP credentials.
    """

    supports_inactive_user = False

    def authenticate(self, *args, **kwargs):
        user = authenticate(*args, **kwargs)
        if user and user.is_active:
            return user

        return None
