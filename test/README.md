# Testing

The acceptance tests run against the LDAP server given by the `LDAP_*` environment variables.
`LDAP_SERVER` selects the server type (`openldap`, `samba` or `adlds`, defaults to `openldap`),
so that the test configurations can be adapted to the server and server specific tests or steps can be skipped.

The GitHub workflow [go.yml](../.github/workflows/go.yml) runs the tests against all three servers,
for OpenLDAP and Samba AD with the same settings as below.

## OpenLDAP

```bash
docker compose up -d
source ldap.env
cd ..
go test ./...
```

## Samba AD

[Samba (Active Directory) Lightweight Directory Services](https://hub.docker.com/r/smblds/smblds)
provides an Active Directory compatible LDAP server.

```bash
docker compose -f docker-compose-samba.yml up -d
source samba.env
cd ..
go test ./...
```

Compared to OpenLDAP, Samba AD
- names an `inetOrgPerson` by `cn` (an RDN like `uid=jimmit01` is rejected),
- returns all object classes of the hierarchy (e.g. `top`, `person`, `organizationalPerson`, `user`, `inetOrgPerson`),
- returns attributes it maintains itself (e.g. `objectGUID`, `whenCreated`), which are ignored by the test configurations.

`testAccConfig` in [ldap/ldap_server_test.go](../ldap/ldap_server_test.go) adapts the test configurations accordingly.

## AD LDS

Active Directory Lightweight Directory Services (AD LDS) is a real Microsoft LDAP server.
It is not available as a container, so the job `test (adlds)` in [go.yml](../.github/workflows/go.yml)
installs it on a Windows runner (`windows-latest`) and runs the tests against it (`LDAP_SERVER=adlds`):

- installs the Windows feature `ADLDS` and creates an instance with the partition `DC=example,DC=com` on port 389,
  importing the schema files for `inetOrgPerson` and `user`,
- creates the AD LDS user `CN=admin,DC=example,DC=com` with a password as administrator of the instance,
  since the provider binds with DN and password (simple bind),
- sets `LDAPServerEnforceIntegrity` to `0`, since newer Windows Server versions reject simple binds
  over plain LDAP by default ("Strong authentication is required").

The tests treat AD LDS like Samba AD. Additionally, the tests relying on a readable `userPassword` are skipped:
in AD LDS `userPassword` is a password attribute, which is subject to the password policy and never returned.
