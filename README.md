# django-ldap-proxy

## Installation
```shell
git clone https://gitee.com/iTraceur/django-ldap-proxy.git
cd django-ldap-proxy
pip install .
```

## Configuration
```python
# Authenticate
AUTH_PROVIDER = 'LDAP'  # or 'system'

if AUTH_PROVIDER == 'LDAP':
    AUTHENTICATION_BACKENDS = (
        'django_ldap_proxy.auth.LDAPBackend',
    )
    LDAP_DOMAIN_SLICE = ('example', 'com')
    # The URL of the LDAP server.
    LDAP_AUTH_URL = "ldap://192.168.100.100:389"

    # Whether the LDAP ppolicy module enabled.
    LDAP_PPOLICY_ENABLED = False

    # The LDAP search base for looking up users.
    LDAP_AUTH_SEARCH_BASE = f"ou=People,dc={LDAP_DOMAIN_SLICE[0]},dc={LDAP_DOMAIN_SLICE[1]}"
    LDAP_POLICY_SEARCH_BASE = f'ou=policies,dc={LDAP_DOMAIN_SLICE[0]},dc={LDAP_DOMAIN_SLICE[1]}'
    # User model fields mapped to the LDAP
    # attributes that represent them.
    LDAP_AUTH_USER_FIELDS = {
        "username": "cn",
        "email": "mail",
        "mobile": "mobile"
    }
    LDAP_AUTH_CONNECTION_USERNAME = 'ldapadminuser'
    LDAP_AUTH_CONNECTION_PASSWORD = 'ldapadminpassword'
    LDAP_DEFAULT_PASSWORD = 'defaultpassword'

    # Initiate TLS on connection.
    LDAP_AUTH_USE_TLS = False
    # The LDAP class that represents a user.
    LDAP_AUTH_OBJECT_CLASS = "inetOrgPerson"
    # A tuple of django model fields used to uniquely identify a user.
    LDAP_AUTH_USER_LOOKUP_FIELDS = ("username",)
    # Set connection/receive timeouts (in seconds) on the underlying `ldap3` library.
    LDAP_AUTH_CONNECT_TIMEOUT = None
    LDAP_AUTH_RECEIVE_TIMEOUT = None
    RAISE_EXCEPTION = True
```
