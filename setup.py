import sys

from setuptools import find_packages, setup

py_version = sys.version_info[:2]

if py_version < (3, 6):
    raise RuntimeError('django-ldap-proxy requires Python 3.6 or above.')

REQUIRES = [
    'Django==3.1',
    'ldap3==2.8',
    'passlib==1.7.2',
    'python-dateutil==2.8.1'
]

CLASSIFIERS = [
    "Programming Language :: Python :: 3.6",
    "Operating System :: OS Independent",
]

setup(
    name='django_ldap_proxy',
    version='0.1.0',
    packages=find_packages(),
    url='',
    license='MIT',
    author='itraceur',
    author_email='',
    description='LDAP proxy for django',
    classifiers=CLASSIFIERS,
    install_requires=REQUIRES,
    zip_safe=False,
)
