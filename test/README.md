# Testing

The acceptance tests run against the LDAP server given by the `LDAP_*` environment variables.
`LDAP_SERVER` selects the server type (`openldap` or `samba`, defaults to `openldap`),
so that the test configurations can be adapted to the server and server specific tests or steps can be skipped.

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
