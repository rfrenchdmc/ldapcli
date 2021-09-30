#!/usr/bin/env python

from distutils.core import setup

with open('requirements.txt') as f:
    deps = [x for x in f.readlines()]

setup(name="LdapCLI",
    version="1.0",
    description="LDAP user and group management via CLI",
    author="Roy French",
    author_email="royfrench@datamachines.io",
    packages=['ldapcli',],
    package_dir={'': 'src'},
    keywords="ldap cli",
    install_requires = deps,
    scripts=['scripts/ldapcli']
    )