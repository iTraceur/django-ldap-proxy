"""
Some useful LDAP utilities.
"""

import binascii
import re

from django.contrib.auth import get_user_model
from django.utils.encoding import force_text
from django.utils.module_loading import import_string

from django_ldap_proxy.conf import config


def import_func(func):
    if callable(func):
        return func
    elif isinstance(func, str):
        return import_string(func)
    raise AttributeError("Expected a function {0!r}".format(func))


def clean_ldap_name(name):
    """
    Transforms the given name into a form that
    won't interfere with LDAP queries.
    """
    return re.sub(
        r'[^a-zA-Z0-9 _\-.@:*]',
        lambda c: "\\" + force_text(binascii.hexlify(c.group(0).encode("latin-1", errors="ignore"))).upper(),
        force_text(name),
    )


def convert_model_fields_to_ldap_fields(model_fields):
    """
    Converts a set of model fields into a set of corresponding
    LDAP fields.
    """
    return {
        config.LDAP_AUTH_USER_FIELDS[field_name]: field_value
        for field_name, field_value
        in model_fields.items()
    }


def format_search_filter(model_fields):
    """
    Creates an LDAP search filter for the given set of model
    fields.
    """
    ldap_fields = convert_model_fields_to_ldap_fields(model_fields)
    ldap_fields["objectClass"] = config.LDAP_AUTH_OBJECT_CLASS
    search_filters = import_func(config.LDAP_AUTH_FORMAT_SEARCH_FILTERS)(ldap_fields)
    return "(&{})".format("".join(search_filters))


def clean_user_data(model_fields):
    """
    Transforms the user data loaded from
    LDAP into a form suitable for creating a user.
    """
    model_fields['email'] = '{username}@{domain}'.format(username=model_fields['username'],
                                                         domain='.'.join(config.LDAP_DOMAIN_SLICE))
    return model_fields


def format_username_openldap(model_fields):
    """
    Formats a user identifier into a username suitable for
    binding to an OpenLDAP server.
    """
    return "{user_identifier},{search_base}".format(
        user_identifier=",".join(
            "{attribute_name}={field_value}".format(
                attribute_name=clean_ldap_name(field_name),
                field_value=clean_ldap_name(field_value),
            )
            for field_name, field_value
            in convert_model_fields_to_ldap_fields(model_fields).items()
        ),
        search_base=config.LDAP_AUTH_SEARCH_BASE,
    )


def format_admin_openldap(model_fields):
    """
    Formats admin identifier into a username suitable for
    binding to an OpenLDAP server.
    """
    return "{user_identifier},{search_base}".format(
        user_identifier=",".join(
            "{attribute_name}={field_value}".format(
                attribute_name=clean_ldap_name(field_name),
                field_value=clean_ldap_name(field_value),
            )
            for field_name, field_value
            in convert_model_fields_to_ldap_fields(model_fields).items()
        ),
        search_base=f"dc={config.LDAP_DOMAIN_SLICE[0]},dc={config.LDAP_DOMAIN_SLICE[1]}",
    )


def format_username_active_directory(model_fields):
    """
    Formats a user identifier into a username suitable for
    binding to an Active Directory server.
    """
    username = model_fields["username"]
    if config.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN:
        username = "{domain}\\{username}".format(
            domain=config.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN,
            username=username,
        )
    return username


def format_username_active_directory_principal(model_fields):
    """
    Formats a user identifier into a username suitable for
    binding to an Active Directory server.
    """
    username = model_fields["username"]
    if config.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN:
        username = "{username}@{domain}".format(
            username=username,
            domain=config.LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN,
        )
    return username


def sync_user_relations(user, ldap_attributes):
    # do nothing by default
    pass


def format_search_filters(ldap_fields):
    return [
        "({attribute_name}={field_value})".format(
            attribute_name=clean_ldap_name(field_name),
            field_value=clean_ldap_name(field_value),
        )
        for field_name, field_value
        in ldap_fields.items()
    ]


def get_or_create_user(user_data):
    """
    Returns a Django user for the given LDAP user data.

    If the user does not exist, then it will be created.
    """

    attributes = user_data.get("attributes")
    if attributes is None:
        return None

    # Create the user data.
    user_fields = {
        field_name: (
            attributes[attribute_name][0]
            if isinstance(attributes[attribute_name], (list, tuple)) else
            attributes[attribute_name]
        )
        for field_name, attribute_name
        in config.LDAP_AUTH_USER_FIELDS.items()
        if attribute_name in attributes
    }
    user_fields = import_func(config.LDAP_AUTH_CLEAN_USER_DATA)(user_fields)
    # Create the user lookup.
    user_lookup = {
        field_name: user_fields.pop(field_name, "")
        for field_name
        in config.LDAP_AUTH_USER_LOOKUP_FIELDS
    }
    # Update or create the user.
    user, created = get_user_model().objects.update_or_create(
        defaults=user_fields,
        **user_lookup
    )
    # If the user was created, set them an unusable password.
    if created:
        user.set_unusable_password()
        user.save()
    # Update relations
    import_func(config.LDAP_AUTH_SYNC_USER_RELATIONS)(user, attributes)
    # All done!
    return user
