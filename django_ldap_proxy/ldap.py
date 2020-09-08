"""
Low-level LDAP hooks.
"""

import logging
import traceback
from contextlib import contextmanager
from time import time

import ldap3
from dateutil import parser
from ldap3.core.exceptions import LDAPException, LDAPOperationResult
from passlib.hash import ldap_salted_sha1

from .conf import config
from .utils import format_search_filter, format_username_openldap, format_admin_openldap

logger = logging.getLogger(__name__)

_admin_connection = None


def format_user_dn(**kwargs):
    if frozenset(kwargs.keys()) != frozenset(config.LDAP_AUTH_USER_LOOKUP_FIELDS):
        return None
    kwargs = {
        key: value
        for key, value
        in kwargs.items()
        if value
    }
    user_dn = format_username_openldap(kwargs)
    return user_dn


def format_admin_dn(**kwargs):
    if frozenset(kwargs.keys()) != frozenset(config.LDAP_AUTH_USER_LOOKUP_FIELDS):
        return None
    kwargs = {
        key: value
        for key, value
        in kwargs.items()
        if value
    }
    username = format_admin_openldap(kwargs)
    return username


class Connection(object):
    """
    A connection to an LDAP server.
    """

    def __init__(self, conn):
        """
        Creates the LDAP connection.

        No need to call this manually, the `connection()` context
        manager handles initialization.
        """
        self.ldap_connection = conn

    def search(self, search_filter, search_base=config.LDAP_AUTH_SEARCH_BASE,
               attributes=ldap3.ALL_ATTRIBUTES, size_limit=0):
        with self.ldap_connection as c:
            result = c.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes,
                get_operational_attributes=True,
                size_limit=size_limit
            )
            return result

    def add(self, dn, object_class=None, attributes=None, controls=None):
        with self.ldap_connection as c:
            c.add(dn, object_class=object_class, attributes=attributes, controls=controls)
            return bool(self.ldap_connection.response)

    def modify(self, dn, changes, controls=None):
        with self.ldap_connection as c:
            c.modify(dn, changes, controls=controls)
            return bool(self.ldap_connection.response)

    def delete(self, dn, controls=None):
        with self.ldap_connection as c:
            c.delete(dn, controls=controls)
            return bool(self.ldap_connection.response)

    def get_user(self, **kwargs):
        """
        Returns the user with the given identifier.

        The user identifier should be keyword arguments matching the fields
        in config.LDAP_AUTH_USER_LOOKUP_FIELDS.
        """
        # Search the LDAP database.
        self.search(search_filter=format_search_filter(kwargs), size_limit=1)
        res = self.ldap_connection.response
        if res:
            return res[0]

    def add_user(self, user_dn, object_class=None, attributes=None):
        if isinstance(object_class, str):
            object_class = list({object_class, config.LDAP_AUTH_OBJECT_CLASS})
        elif isinstance(object_class, (list, tuple)):
            object_class = list(set(object_class).union({config.LDAP_AUTH_OBJECT_CLASS}))
        else:
            object_class = config.LDAP_AUTH_OBJECT_CLASS
        return self.add(user_dn, object_class=object_class, attributes=attributes)

    def create_user(self, username, password, mail=None, mobile=None, sn=None):
        user_dn = format_user_dn(username=username)
        if not user_dn:
            raise LDAPOperationResult(f'Invalid username {username} to user dn')

        if not self.get_user(username=username):
            attributes = {
                'cn': username,
                'sn': sn or username,
                'userPassword': ldap_salted_sha1.hash(password),
                'pwdReset': 'TRUE'
            }
            if mail:
                attributes['mail'] = mail
            if mobile:
                attributes['mobile'] = mobile
            return self.add_user(user_dn, attributes=attributes)

    def modify_user(self, username, **kwargs):
        ldap_user = self.get_user(username=username)
        if not ldap_user:
            raise LDAPOperationResult(f'{username} does not exists')

        user_dn = format_user_dn(username=username)
        if not user_dn:
            raise LDAPOperationResult(f'Invalid username {username} to user dn')

        changes = {}
        attrs = ldap_user['attributes']
        for key, value in kwargs.items():
            cur_value = attrs.get(key, None)
            if not cur_value and value:
                changes[key] = [(ldap3.MODIFY_ADD, [str(value)])]
            if cur_value and value:
                changes[key] = [(ldap3.MODIFY_REPLACE, [str(value)])]
            if cur_value and not value:
                changes[key] = [(ldap3.MODIFY_DELETE, cur_value)]
        return self.modify(user_dn, changes=changes)

    def delete_user(self, username):
        if not self.get_user(username=username):
            raise LDAPOperationResult(f'{username} does not exists')

        user_dn = format_user_dn(username=username)
        if not user_dn:
            raise LDAPOperationResult(f'Invalid username {username} to user dn')

        return self.delete(user_dn)

    def change_password(self, username, old_password, new_password):
        with self.ldap_connection as c:
            c.extend.standard.modify_password(
                user=username,
                old_password=old_password,
                new_password=new_password
            )

    def validate_password(self, username, password):
        self.search(search_filter=f'(cn={username})')
        response = self.ldap_connection.response[0]
        if response:
            hashed_password = response['attributes']['userPassword'][0]
            return ldap_salted_sha1.verify(password, hashed_password)

        logger.warning("LDAP user lookup failed")
        return None

    def get_pwd_max_age(self, cn='default'):
        try:
            self.search(search_base=config.LDAP_POLICY_SEARCH_BASE, search_filter=f'(cn={cn})')
            res = self.ldap_connection.response[0]
            return int(res['attributes']['pwdMaxAge'][0])
        except:
            logger.warning(traceback.format_exc())

        return 0

    def get_pwd_changed_time(self, username):
        try:
            self.search(search_filter=f'(cn={username})')
            res = self.ldap_connection.response[0]
            dt = parser.parse(res['attributes']['pwdChangedTime'][0])
            return int(dt.timestamp())
        except:
            logger.warning(traceback.format_exc())

        return int(time())

    def get_pwd_validity_period(self, username):
        pwd_max_age = self.get_pwd_max_age()
        pwd_changed_time = self.get_pwd_changed_time(username)
        passed_time = int(time()) - pwd_changed_time
        if pwd_max_age == 0:
            return -1
        if pwd_max_age > passed_time:
            return pwd_max_age - passed_time
        else:
            return 0


def get_ldap3_connection(username, password):
    server = ldap3.Server(
        config.LDAP_AUTH_URL,
        allowed_referral_hosts=[("*", True)],
        get_info=ldap3.NONE,
        connect_timeout=config.LDAP_AUTH_CONNECT_TIMEOUT,
    )
    params = {
        'client_strategy': ldap3.SYNC,
        'user': username,
        'password': password,
        'raise_exceptions': True,
        'receive_timeout': config.LDAP_AUTH_RECEIVE_TIMEOUT,
    }
    return ldap3.Connection(server, **params)


@contextmanager
def connection(**kwargs):
    """
    Creates and returns a connection to the LDAP server.

    The user identifier, if given, should be keyword arguments matching the fields
    in config.LDAP_AUTH_USER_LOOKUP_FIELDS, plus a `password` argument.
    """
    # Format the DN for the username.
    password = kwargs.pop("password", None)
    user_dn = format_user_dn(**kwargs)

    # Connect.
    try:
        c = get_ldap3_connection(user_dn, password)
    except LDAPException as ex:
        logger.warning("LDAP connect failed: {ex}".format(ex=ex))
        yield None
    else:
        # Configure.
        try:
            # Start TLS, if requested.
            if config.LDAP_AUTH_USE_TLS:
                c.start_tls(read_server_info=False)
            # Perform initial authentication bind.
            c.bind(read_server_info=True)

            # Return the connection.
            logger.info("LDAP connect succeeded")
            yield Connection(c)
        except LDAPException as ex:
            logger.warning("LDAP bind failed: {ex}".format(ex=ex))
            yield None
        finally:
            c.unbind()


def admin_connection():
    global _admin_connection
    if _admin_connection:
        return _admin_connection

    assert config.LDAP_AUTH_CONNECTION_USERNAME and config.LDAP_AUTH_CONNECTION_PASSWORD, \
        'Need LDAP_AUTH_CONNECTION_USERNAME and LDAP_AUTH_CONNECTION_PASSWORD config。'

    admin_dn = format_admin_dn(username=config.LDAP_AUTH_CONNECTION_USERNAME)
    password = config.LDAP_AUTH_CONNECTION_PASSWORD

    try:
        c = get_ldap3_connection(admin_dn, password)
    except LDAPException as exc:
        logger.warning("LDAP connect failed: {exc}".format(exc=exc))
        raise exc

    try:
        # Start TLS, if requested.
        if config.LDAP_AUTH_USE_TLS:
            c.start_tls(read_server_info=False)
        # Perform initial authentication bind.
        c.bind(read_server_info=True)
        # Return the connection.
        logger.info("LDAP connect succeeded")
        _admin_connection = Connection(c)
        return _admin_connection
    except LDAPException as exc:
        logger.warning("LDAP bind failed: {exc}".format(exc=exc))
        raise exc


def add_user(username, password, email=None, mobile=None, sn=None):
    conn = admin_connection()
    if not conn:
        raise LDAPOperationResult('LDAP connect failed')

    conn.create_user(username, password, email, mobile, sn)


def modify_user(username, password=None, email=None, cell_phone=None, full_name=None):
    conn = admin_connection()
    if not conn:
        raise LDAPOperationResult('LDAP connect failed')

    changes = {
        'mail': email,
        'mobile': cell_phone,
        'sn': full_name
    }
    if password:
        changes['userPassword'] = ldap_salted_sha1.hash(password)
    conn.modify_user(username, **changes)


def delete_user(username):
    conn = admin_connection()
    if not conn:
        raise LDAPOperationResult('LDAP connect failed')

    conn.delete_user(username)


def change_password(username, old_password, new_password):
    dn = format_user_dn(username=username)
    if not dn:
        return

    with connection(username=username, password=old_password) as c:
        if not c:
            return LDAPOperationResult('LDAP connect failed')
        try:
            c.change_password(dn, old_password, new_password)
        except LDAPOperationResult as exc:
            return exc


def change_password_admin(username, old_password, new_password):
    user_dn = format_user_dn(username=username)
    conn = admin_connection()
    if not conn:
        return False
    return conn.change_password(user_dn, old_password, new_password)
