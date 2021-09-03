#!/usr/bin/env python

from distutils.core import setup

setup(name="LdapCLI",
    version="1.0",
    description="LDAP user and group management via CLI",
    author="Roy French",
    author_email="royfrench@datamachines.io",
    packages=['ldapcli',],
    package_dir={'': 'src'},
    keywords="ldap cli",
    install_requires = [
        'pyaml',
        'ldap3',
        'click'
    ],
    scripts=['scripts/ldapcli']
    )