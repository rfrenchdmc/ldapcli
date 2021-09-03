# ldapcli
Manage LDAP users and groups via CLI


## Getting Started

1. Clone repo - `git clone git@github.com:rfrenchdmc/ldapcli.git`
2. Change dir - `cd ldapcli`
3. Install - `pip install .`
4. Configure - `ldapcli profile add`
5. Run - `ldapcli`

- help - Information can be received using the `--help` or '-h' flag

## Profiles
LDAPCli allows for the creation and management of multiple profiles.
A profile is equivalent to and LDAP server allowing the client to 
be aware and manage multiple LDAP servers.  LDAPCli has `default` 
profile that is used if no profile is provided.   

Profiles can be managed using the `profile` command.  The 
following sub-subcommands are available:

| command | subcommand | description |
| ------- | ---------- | ----------- |
| create  | | Create a profile  |
| remove | | Remove a profile |
| display | | Display one or all profiles |


Profiles configuration can be stored in any file and specified via 
command line.  The default location for the config file is 
`$HOME/.ldapcli.yml`

## Users
Managing users is primary purpose of LDAPCli.  User management is 
achieved via the `user` command.  The following sub-commands 
are available:

| command | subcommand | description |
| ------- | ---------- | ----------- |
| create  | | Create a user  |
| passwd  | | Reset a users password |
| remove  | | Remove a user |
| display | | Display a user's information |
| group   | | Manage a user's groups
| group   | add | Add a user to a group |
| group   | remove | Remove a user from group |

## Groups
LDAPCli can manage groups and group membership via the 
`group` subcommand.

| command | subcommand | description |
| ------- | ---------- | ----------- |
| create  | | Create a group  |
| remove  | | Remove a group |
| display | | Display a groups information and membership |
| user    | | Manage users in a group |
| user    | add | Add one or more users to a group |
| user    | remove | Remove one or more users from a group |
 



