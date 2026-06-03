# Testing

## OpenLDAP (Default)

```bash
docker compose up -d
source ldap.env
cd ..
go test ./...
```

## Samba AD LDS (for Active Directory features)

Samba AD provides Active Directory-compatible LDAP, useful for testing features like `recursive_delete` (Tree Delete Control).

### Using Docker/Podman on Linux or macOS

```bash
docker compose -f docker-compose-samba.yml up -d
source ldap-samba.env
cd ..
go test ./...
```

### Using Podman on Windows (WSL)

**Important:** Podman must be installed directly in WSL, not via Podman Desktop for Windows. The Windows Podman machine uses WSL2 networking which does not properly forward ports to Windows, making the LDAP container unreachable from the host.

Start the Samba container with high ports (ports below 1024 require root):

```bash
podman run -d --name smblds-test \
   -p 3389:389 \
   -p 3636:636 \
   -e REALM="EXAMPLE.COM" \
   -e DOMAIN="EXAMPLE" \
   -e ADMIN_PASS="Passw0rd" \
   -e INSECURE_LDAP=true \
   --rm docker.io/smblds/smblds
```

### Verifying Connectivity

For GUI exploration from Windows, connect using the WSL IP address (run `hostname -I` in WSL) on port 3389:

- [SysInternals AD Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer)
