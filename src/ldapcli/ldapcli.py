#!/usr/bin/env python

import click
import ldap3
import yaml
import os
import os.path
from tabulate import tabulate
from copy import copy
import logging

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

# pasword field = userPassowrd
LOG_LEVELS = {
    0: logging.ERROR,
    1: logging.WARNING,
    2: logging.INFO,
    3: logging.DEBUG,
}

CONFIG_VERSION = 'version'
CONFIG_PROFILES = 'profiles'
CONFIG_DEFAULTS = 'defaults'

CTX_CONFIG_FILE = 'config-file'
CTX_CONNECT = 'connect'
CTX_CONFIG = 'ldap-config'

PROF_HOST_URL = 'host_url'
PROF_BIND_DN = 'bind_dn'
PROF_BIND_PWD = 'bind_pwd'
PROF_USER_SEARCH_DN = 'user_search_dn'
PROF_USER_ADD_TEMPLATE = 'user_add_template'

PROF_GROUP_SEARCH_DN = 'group_search_dn'
PROF_GROUP_ADD_TEMPLATE = 'group_add_template'

PROFILE_FIELDS = [
    (PROF_HOST_URL, True),
    (PROF_BIND_DN, True),
    (PROF_USER_SEARCH_DN, True),
    (PROF_USER_ADD_TEMPLATE, False),
    (PROF_GROUP_SEARCH_DN, True),
    (PROF_GROUP_ADD_TEMPLATE, False)
]

_verbosity = 1

LATEST_CONFIG_VERSION = '1.0'

GROUP_SPACING = '\n\t              '

GROUP_ID_FIELD = 'cn'
USER_ID_FIELD = 'uid'

_logger = logging.getLogger('ldapcli')

class LdapConfig:

    def __init__(self, d, c_profile='default'):
        if d:
            self.version = d.get("version")
            self.defaults = d.get("defaults", {})
            self.profiles = d.get("profiles")
        else:
            self.version = LATEST_CONFIG_VERSION
            self.defaults = {}
            self.profiles = {}

        self.current_profile_name = c_profile

    @classmethod
    def load(cls, fn, c_profile='default'):
        try:
            with open(fn) as f:
                conf = yaml.load(f, Loader=Loader)
        except FileNotFoundError:
            conf = {}

        return LdapConfig(conf, c_profile)

    def to_dict(self):
        return dict(version=".1", defaults=self.defaults, profiles=self.profiles)

    def to_yaml(self):
        return yaml.dump(self.to_dict())

    def write(self, fn):
        with open(fn, 'w') as f:
            f.write(self.to_yaml())

    def get(self, k, d=None):
        return self.current_profile.get(k, self.defaults.get(k))

    @property
    def host_url(self):
        return self.get(PROF_HOST_URL)

    @property
    def bind_dn(self):
        return self.get(PROF_BIND_DN)

    @property
    def user_search_base(self):
        return self.get(PROF_USER_SEARCH_DN)

    @property
    def group_search_base(self):
        return self.get(PROF_GROUP_SEARCH_DN)

    @property
    def current_profile(self):
        return self.profiles.get(self.current_profile_name, {})

    def update_profile(self, new_values):
        current_values = self.current_profile().copy()

        for k, v in new_values.items():
            if v is not None:
                current_values[k] = v

        for c in PROFILE_FIELDS:
            if c[1]:
                if c[0] not in current_values or not current_values[c[0]]:
                    raise InvalidEntry(f"{c} not found in new profile")

        self.profiles[self.current_profile_name] = current_values


def __normalize_names(nm, base, id_field):
    if nm.startswith(f"{id_field}="):
        dn = nm
        name = nm[len(id_field) + 1:nm.index(',')]
    else:
        name = nm
        dn = f"{id_field}={nm},{base}"

    return name, dn


def _normalize_user_names(nm, base):
    return __normalize_names(nm, base, USER_ID_FIELD)


def _normalize_group_names(nm, base):
    return __normalize_names(nm, base, GROUP_ID_FIELD)


def _print_entry(entry, attributes, show_empty=True, separator=','):
    print(entry.entry_dn)
    for a in attributes:

        v = entry.entry_attributes_as_dict[a]

        if v or show_empty:
            print(f"\t{a}: {separator.join(v)}")


def set_verbosity(v):
    global _verbosity
    _verbosity = v

    _logger.setLevel(LOG_LEVELS.get(_verbosity, logging.INFO))

class InvalidEntry(Exception):
    def __init__(self, msg):
        super().__init__(msg)


def _retrieve_value(v):
    if v is None:
        return None

    if v.startswith("@"):
        fn = v[1:]
        with open(fn, 'r') as f:
            return f.read()

    return v


def _connect_ldap(ctx):
    config = ctx.obj[CTX_CONFIG]

    passwd = config.get(PROF_BIND_PWD)

    if not passwd:
        passwd = click.prompt("Bind Password", hide_input=True)

    host = config.host_url
    dn = config.bind_dn

    _logger.debug(f"Connecting to {host} with {dn}")
    s = ldap3.Server(host)
    c = ldap3.Connection(s, user=dn, password=passwd)

    if not c.bind():
        raise click.ClickException("Failed to bind to LDAP server")

    ctx.obj[CTX_CONNECT] = c


def _add_user_to_groups(config, connect, user_dn, user_id, groups):
    if isinstance(groups, str):
        groups = [groups]

    for g in groups:
        g_name, g_dn = _normalize_group_names(g, config.group_search_base)

        _logger.debug(f"Adding uniqueMember={user_dn} to group {g_dn}")
        _logger.debug(f"Adding memberUid={user_id} to group {g_dn}")

        mods = {
            'uniqueMember': [(ldap3.MODIFY_ADD, [user_dn])],
            'memberUid': [(ldap3.MODIFY_ADD, [user_id])]
        }

        if not connect.modify(g_dn, mods):
            raise click.ClickException(f"Failed to add user to group {g}: {connect.result}")


def _remove_user_from_groups(config, connect, user_dn, groups):
    for g in groups:
        g_name, g_dn = _normalize_group_names(g, config.group_search_base)
        _logger.debug( f"Removing {user_dn} from group {g_dn}")
        if not connect.modify(g_dn, {'uniqueMember': [(ldap3.MODIFY_DELETE, [user_dn])]}):
            raise click.ClickException(f"Failed to remove user to group {g}: {connect.result}")


def _verify_entity_exists(ctx, entity, base, id_field):
    connect = ctx.obj[CTX_CONNECT]
    uid, dn = __normalize_names(entity, base, id_field)

    if not connect.search(base, f"({id_field}={uid})"):
        if connect.last_error:
            raise click.ClickException(f"Failed to find entity {connect.result}")

    return uid, dn


def _verify_user_exists(ctx, user_dn):
    conf = ctx.obj[CTX_CONFIG]
    return _verify_entity_exists(ctx, user_dn, conf.user_search_base, USER_ID_FIELD)


def _verify_group_exists(ctx, grp):
    conf = ctx.obj[CTX_CONFIG]
    return _verify_entity_exists(ctx, grp, conf.group_search_base, GROUP_ID_FIELD)


def _create_group(ctx, group_name, group_id, description=None):
    ctx.ensure_object(dict)
    obj = ctx.obj
    conf = obj[CTX_CONFIG]

    group_name, group_dn = _normalize_group_names(group_name, conf.group_search_base)

    _logger.debug(f"Adding Group name={group_name} dn={group_dn}")

    args = {
        GROUP_ID_FIELD: group_name
    }

    cls = ['top', 'groupOfUniqueNames', 'posixGroup']

    args['gidNumber'] = group_id

    if description:
        args['description'] = description

    connect = obj[CTX_CONNECT]
    connect.add(group_dn, cls, args)

    return group_name, group_dn

@click.group()
@click.option("--config-file", "-c", default=os.path.join(os.getenv("HOME"), ".ldapcli.yml"))
@click.option("--profile-name", "-n", default='default')
@click.option("--verbose", "-v", count=True, help="Output level", default=1)
@click.pass_context
def cli(ctx, config_file, profile_name, verbose):
    ctx.ensure_object(dict)
    set_verbosity(verbose)

    _logger.debug(f"Loading profile {profile_name} from {config_file}")

    ctx.obj[CTX_CONFIG_FILE] = config_file
    ctx.obj[CTX_CONFIG] = LdapConfig.load(config_file, profile_name)


@cli.result_callback()
@click.pass_context
def user_cleanup(ctx, result, **kwargs):
    if CTX_CONNECT in ctx.obj:
        _logger.debug("Closing connection")
        ctx.obj[CTX_CONNECT].unbind()


@cli.group()
@click.pass_context
def user(ctx):
    _connect_ldap(ctx)


@user.command(name='create')
@click.option("--username", "-u", help="login name for user", required=True, prompt=True)
@click.option("--commonname", "-c", help="Common name for user", required=True, prompt=True)
@click.option("--public-key", "-p", help="Public key for user")
@click.option("--uid", help="Specify user id")
@click.option("--home", help="Specify user's home directory")
@click.option("--gid", help="Specify group id")
@click.option("--surname", help="Specify user's surname", required=True, prompt=True)
@click.option("--email", help="Specify user's email", required=True, prompt=True)
@click.option("--group", '-g', multiple=True, default=[], help="group to add users")
@click.pass_context
def user_create(ctx, username, commonname, public_key, uid, gid, home, surname, email, group):
    ctx.ensure_object(dict)
    obj = ctx.obj
    conf = obj[CTX_CONFIG]
    connect = obj[CTX_CONNECT]

    next_id = 1

    if uid is None:
        if not connect.search(conf.user_search_base, "(objectclass=person)", attributes=['uid', 'gidNumber']):
            # Check if real error or just no records
            if connect.last_error:
                raise click.ClickException(f"Failed to query for uid: {connect.result}")

        max_uid = 100
        max_gid = 100

        for r in connect.entries:
            max_uid = max(max_uid, r.entry_attributes_as_dict.get('uidNumber', [0])[0])
            tgid = r.entry_attributes_as_dict.get('gidNumber', [0])
            if tgid == []:
                tgid = 0
            else:
                tgid = tgid[0]
            max_gid = max(max_gid, tgid)

        next_id = max(max_uid, max_gid) + 1

        _logger.debug(f"Next id: {next_id}")

    if uid:
        if not connect.search(conf.user_search_base, f"(uid={uid})"):
            raise click.ClickException(f"Failed to query for uid: {connect.result}")

        if connect.entries:
            raise click.ClickException(f"Entry with uid {uid} already exists")
    else:
        uid = next_id

    if gid:
        if not connect.search(conf.user_search_base, f"(gidNumber={gid})"):
            raise click.ClickException(f"Failed to query for gid: {connect.result}")

        if connect.entries:
            raise click.ClickException(f"Entry with gid {gid} already exists")
    else:
        gid = next_id

    if not home:
        home = f"/home/{username}"

    username, user_dn = _normalize_user_names(username, conf.user_search_base)

    _logger.debug(f"Creating group: {username} id: {gid}")
    group_name, group_dn = _create_group(ctx, username, gid)
    _add_user_to_groups(conf, connect, user_dn, username, group_name)

    _logger.debug(f"Adding user name: {username} dn: {user_dn}")

    args = {
        'uid': username,
        'uidNumber': next_id,
        'homeDirectory': home,
        'gidNumber': next_id,
        'sn': surname,
        'mail': email,
        'cn': commonname
    }

    if public_key:
        args['sshPublicKey'] = _retrieve_value(public_key)

    cls = ['top', 'account', 'posixaccount', 'inetOrgPerson', 'person', 'inetUser', 'organizationalPerson',
           'ldapPublicKey']

    if not connect.add(user_dn, cls, args):
        raise click.ClickException(f"Failed to create user {user_dn}: {connect.result}")

    _add_user_to_groups(conf, connect, user_dn, username, group)


@user.command(name='passwd')
@click.option("--username", '-u', required=True, help="Username who's password to reset")
@click.pass_context
def user_passwd(ctx, username):
    ctx.ensure_object(dict)
    obj = ctx.obj
    connect = obj[CTX_CONNECT]

    username, user_dn = _verify_user_exists(ctx, username)

    passwd = click.prompt("New Password", confirmation_prompt=True, hide_input=True)

    _logger.debug(f"Resetting password for {user_dn}")
    if not connect.modify(user_dn, dict(userPassword=[(ldap3.MODIFY_REPLACE, passwd)])):
        raise click.ClickException(f"Failed to change password for {user_dn}")


@user.command(name='public-key')
@click.option("--public-key", '-p', required=True)
@click.option("--username", '-u', required=True, help="Username to update")
@click.pass_context
def user_public_key(ctx, username, public_key):
    obj = ctx.obj
    u_name, u_dn = _verify_user_exists(ctx, username)

    pk = _retrieve_value(public_key).encode('utf-8')

    connect = obj[CTX_CONNECT]
    if not connect.modify(u_dn, dict(sshPublicKey=[(ldap3.MODIFY_REPLACE, pk)])):
        raise click.ClickException(f"Failed to change public key for {u_dn}")


@user.command(name='display')
@click.option("--username", '-u', help="Username to search")
@click.option("--attribute", '-a', multiple=True)
@click.option("--show-empty/--hide-empty", default=True, help="Display empty attributes")
@click.pass_context
def user_display(ctx, username, attribute, show_empty):
    connect = ctx.obj['connect']
    config = ctx.obj[CTX_CONFIG]

    if username:
        u_name, u_dn = _normalize_user_names(username, config.user_search_base)
        result = connect.search(config.user_search_base, f'(uid={u_name})', attributes=attribute)

    else:
        result = connect.search(config.user_search_base, '(objectclass=person)', attributes=attribute)

    if result:
        for r in connect.entries:
            _print_entry(r, attribute, show_empty)


@user.command(name='list')
@click.option("--attribute", '-a', multiple=True, default=['dn'])
@click.pass_context
def user_list(ctx, attribute):
    connect = ctx.obj['connect']
    config = ctx.obj[CTX_CONFIG]

    attribute = [x.lower() for x in attribute]
    result = connect.search(config.user_search_base, '(objectclass=person)', attributes=attribute)

    table = []
    if result:
        for r in connect.entries:
            d = r.entry_attributes_as_dict
            d['dn'] = r.entry_dn

            t = [d.get(x) for x in attribute]
            table.append(t)

        print(tabulate(table, headers=attribute))


@user.group(name='group')
def user_group():
    pass


@user_group.command(name='add')
@click.option("--username", '-u', required=True, help="User to add to group")
@click.option("--group", '-g', multiple=True, required=True, help="group to add users")
@click.pass_context
def user_group_add(ctx, username, group):
    connect = ctx.obj['connect']
    config = ctx.obj[CTX_CONFIG]

    username, u_dn = _verify_user_exists(ctx, username)

    _add_user_to_groups(config, connect, u_dn, group)


@user_group.command(name='remove')
@click.option("--username", '-u', required=True, help="User to remove")
@click.option("--group", '-g', multiple=True, required=True, help="groups to remove user")
@click.pass_context
def user_group_add(ctx, username, group):
    connect = ctx.obj['connect']
    config = ctx.obj[CTX_CONFIG]

    username, u_dn = _verify_user_exists(ctx, username)

    _remove_user_from_groups(config, connect, u_dn, group)


@user_group.command(name='display')
@click.option("--username", '-u', required=True, help="User to remove")
@click.pass_context
def user_group_display(ctx, username):
    connect = ctx.obj['connect']
    config = ctx.obj[CTX_CONFIG]

    username, u_dn = _verify_user_exists(ctx, username)

    if not connect.search(config.group_search_base, f"(uniqueMember={u_dn})"):
        if connect.last_error:
            raise click.ClickException(f"Failed to query groups: {connect.result}")

    for r in connect.entries:
        _print_entry(r, [], separator='\n')


@cli.group()
@click.pass_context
def group(ctx):
    _connect_ldap(ctx)


@group.command()
@click.pass_context
def fix_groups(ctx):
    connect = ctx.obj['connect']
    config = ctx.obj[CTX_CONFIG]

    result = connect.search(config.group_search_base, '(objectclass=groupOfUniqueNames)',
                            attributes=['uniqueMember', 'memberUid', 'objectClass', 'gidNumber'])


    next_gid = 20000

    for e in connect.entries:
        mods = {}

        if 'posixGroup' not in e.objectClass.values:
            mods['objectClass'] = [(ldap3.MODIFY_ADD, ['posixGroup'])]
            if not e.gidNumber:
                mods['gidNumber']  = [(ldap3.MODIFY_ADD, [next_gid])]
                next_gid += 1

        for g in e.uniqueMember.values:
            if g != 'cn=Directory Manager':
                uid, udn = _normalize_user_names(g, config.user_search_base)

                if uid not in e.memberUid.values:
                    mods.setdefault('memberUid', []).append((ldap3.MODIFY_ADD, [uid]))

        if mods:
            if not connect.modify(e.entry_dn, mods):
                raise click.ClickException(f"Failed up update group {g}: {connect.result}")

def _convert_values_bytes(d):
    results = {}

    for k, v in d.items():
        if isinstance(v, str):
            v = v.encode('utf-8')
        elif isinstance(v, (tuple, list)):
            v = [x.encode('utf-8') for x in v]

        if v is not None:
            results[k] = v

    return results


@group.command(name='list')
@click.option("--attribute", '-a', multiple=True, default=['dn'])
@click.pass_context
def group_list(ctx, attribute):
    connect = ctx.obj['connect']
    config = ctx.obj[CTX_CONFIG]

    attribute = [x.lower() for x in attribute]
    result = connect.search(config.group_search_base, '(objectclass=groupofuniquenames)', attributes=attribute)

    table = []
    if result:
        for r in connect.entries:
            d = r.entry_attributes_as_dict
            d['dn'] = r.entry_dn

            t = [d.get(x) for x in attribute]
            table.append(t)

        print(tabulate(table, headers=attribute))


@group.command(name="create")
@click.option("--group-name", "-g", required=True, help='Name of group')
@click.option("--description", "-d", default="", help='Description of group')
@click.pass_context
def group_create(ctx, group_name, description):
    _create_group(ctx, group_name, description)


@group.command(name='display')
@click.option("--group-name", "-g", help='Name of group')
@click.option("--attribute", "-a", multiple=True)
@click.pass_context
def group_display(ctx, group_name, attribute):
    connect = ctx.obj[CTX_CONNECT]
    config = ctx.obj[CTX_CONFIG]

    attribute = list(attribute)

    filter = "(objectclass=posixGroup)"
    if group_name:
        filter = f"(&{filter}(cn={group_name}))"

    g_dn = config.group_search_base
    _logger.debug(f"Searching groups in {g_dn}")
    _logger.debug(f"Searching groups filter {filter}")

    if 'uniqueMember' not in attribute:
        attribute.append('uniqueMember')

    results = connect.search(g_dn, filter, attributes=attribute)

    if results:
        for r in connect.entries:
            _print_entry(r, attribute, separator=GROUP_SPACING)
    else:
        raise click.ClickException("Failed to retrieve groups")


@group.command(name='remove')
@click.option("--group", "-g", help='Name of group', required=True)
@click.pass_context
def group_remove(ctx, group):
    ctx.ensure_object(dict)
    obj = ctx.obj
    conf = obj[CTX_CONFIG]

    group_name, group_dn = _normalize_group_names(group, conf.group_search_base)

    _logger.debug(f"Removing Group {group_dn}")
    obj[CTX_CONNECT].delete(group_dn)


@group.group(name='user')
def group_user():
    pass


@group_user.command(name='add')
@click.option("--group", "-g", help='Name of group', required=True)
@click.option("--user", "-u", multiple=True, help="Users to add to group", default=[])
@click.pass_context
def group_user_add(ctx, group, user):
    ctx.ensure_object(dict)
    obj = ctx.obj
    conf = obj[CTX_CONFIG]
    connect = obj[CTX_CONNECT]

    id, dn = _verify_group_exists(ctx, group)

    if not connect.search(conf.group_search_base, f'({GROUP_ID_FIELD}={id})', attributes=['uniqueId']):
        raise click.ClickException(f"Failed to query group {dn}: {connect.result}")

    current_members = set(connect.entries[0].uniqueId.values)

    new_members = []

    for u in user:
        id, u_dn = _normalize_user_names(u, conf.user_search_base)

        if id not in current_members:
            new_members.append((ldap3.MODIFY_ADD, id))

    if new_members:
        if not connect.modify(dn, {'uniqueUid': new_members}):
            raise click.ClickException("Failed to add users to group")


@group_user.command(name='remove')
@click.option("--group", "-g", help='Name of group', required=True)
@click.option("--user", "-u", multiple=True, help="Users to remove from group", default=[])
@click.pass_context
def group_user_remove(ctx, group, user):
    ctx.ensure_object(dict)
    obj = ctx.obj
    conf = obj[CTX_CONFIG]
    connect = obj[CTX_CONNECT]

    id, dn = _verify_group_exists(ctx, group)

    args = []
    for u in user:
        u_id, u_dn = _normalize_user_names(u, conf.user_search_base)
        args.append((ldap3.MODIFY_DELETE, u_dn))

    if not connect.modify(dn, {'uniqueMember': args}):
        raise click.ClickException(f"Failed to remove users from group {dn}")


@cli.group()
def profile():
    pass


@profile.command(name="display", help="Display configs")
@click.option("--all", '-a', is_flag=True, default=False, help="Display all configs")
@click.pass_context
def profile_display(ctx, all):
    ctx.ensure_object(dict)

    conf = ctx.obj[CTX_CONFIG]
    if not all:
        print(yaml.dump({conf.current_profile_name: conf.current_profile()}))
    else:
        print(yaml.dump(conf.profiles))


def prompt(txt, arg_value=None, current_value=None, required=False):
    value = arg_value

    if not value:
        if required:
            while not value:
                value = click.prompt(txt, default=current_value, show_default=True)
        else:
            value = click.prompt(txt, default=current_value, show_default=True)

    return value


@profile.command(name="add", help='Add or update server')
@click.option("--host-url", "-H", help="URL for the LDAP server")
@click.option("--bind-dn", '-b', help="Bind DN for the user to connect")
@click.option("--user-search-dn", help='DN to search for users')
@click.option("--group-search-dn", help='DN to search for groups')
@click.option("--group-template", default="templates/group_template.ldif", help='LDIF template file to add Groups')
@click.option("--user-template", default="templates/user_template.ldif", help='LDIF template file to add User')
@click.pass_context
def profile_add(ctx, host_url, bind_dn, group_search_dn, user_search_dn,
                group_template, user_template):
    conf = ctx.obj[CTX_CONFIG]
    new_config = {
        PROF_HOST_URL: prompt("Host URL", host_url, conf.get(PROF_HOST_URL), required=True),
        PROF_BIND_DN: prompt("Bind DN", bind_dn, conf.get(PROF_BIND_DN), required=True),
        PROF_USER_SEARCH_DN: prompt("User search DN", user_search_dn, conf.get(PROF_USER_SEARCH_DN), required=True),
        PROF_USER_ADD_TEMPLATE: prompt("User LDIF template", user_template, conf.get(PROF_USER_ADD_TEMPLATE),
                                       required=False),
        PROF_GROUP_SEARCH_DN: prompt("Group Search DN", group_search_dn, conf.get(PROF_GROUP_SEARCH_DN), required=True),
        PROF_GROUP_ADD_TEMPLATE: prompt("Group LDIF template", group_template, conf.get(PROF_GROUP_ADD_TEMPLATE),
                                        required=False)
    }

    conf = ctx.obj[CTX_CONFIG]
    try:
        conf.update_profile(new_config)
        conf.write(ctx.obj[CTX_CONFIG_FILE])
    except InvalidEntry as e:
        raise click.ClickException(e)


@profile.command(name="update")
@click.option("--host-url", "-H", help="URL for the LDAP server")
@click.option("--bind-dn", '-b', help="Bind DN for the user to connect")
@click.option("--user-search-dn", help='DN to search for users')
@click.option("--group-search-dn", help='DN to search for groups')
@click.option("--group-template", default="templates/group_template.ldif", help='LDIF template file to add Groups')
@click.option("--user-template", default="templates/user_template.ldif", help='LDIF template file to add User')
@click.pass_context
def profile_update(ctx, host_url, bind_dn, group_search_dn, user_search_dn,
                   group_template, user_template):
    raise click.ClickException("NOT IMPLEMENTED")


@profile.command(name='remove')
@click.pass_context
def profile_remove(ctx):
    conf = ctx.obj[CTX_CONFIG]

    _logger.debug(f"Removing profile {conf.current_profile_name}")
    conf.profiles.pop(conf.current_profile_name)
    conf.write(ctx.obj[CTX_CONFIG_FILE])


if __name__ == '__main__':
    cli()
