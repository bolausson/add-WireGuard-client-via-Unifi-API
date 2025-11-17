# add-WireGuard-client-via-Unifi-API
Add a WireGuard client to a Unifi Wireguard-Server using the API

With the help of some network logging and some LLM support,
I was able to instrument the Unifi proxy/network/v2/api to manage the WireGurad clients.

This script was tested against a Unifi UDM SE running:
* UnifiOS: 5.0.4
* Network: 10.0.152

The script can:
* list users
* add users
* delete users

Per default, the resulting WireGuard configuration file for the new client is printed to stdout.
Optionally it can be saved to a file as well.

Verbose output will print the requests and the according response.

Defaults can be stored in ~/unifi.conf file e.g.:
```
[unifi]
gateway = unifi.local
username = admin
password = SuperSecretPw # Optional, will falback to promt if empy
site_id = default
verify_tls = false
default_dns = 1.1.1.1
AdditionalAllowedIPs = 10.0.0.0/22
DefaultWGconfFolder = /home/bolausson/wgconfig
DefaultWGnetworkName = TestServer
```

## API enpoints:
| Action | Endpoint (relative to https://{controller}) | Method | Parameters sent | Notes |
|---|---|---|---|---|
| List WireGuard networks | /proxy/network/api/s/{site_id}/rest/networkconf | GET | none | Filter client-side for `vpn_type == "wireguard-server"` |
| List WireGuard users (clients) | /proxy/network/v2/api/site/{site_id}/wireguard/{network_id}/users | GET | Query: `networkId={network_id}` | Path carries `{network_id}`; UI also sends it as query |
| Add WireGuard user (batch) | /proxy/network/v2/api/site/{site_id}/wireguard/{network_id}/users/batch | POST | JSON body: `[ { "name": "string", "interface_ip": "A.B.C.D", "public_key": "base64" } ]` | Array payload; controller returns created user(s) |
| Delete WireGuard user(s) (batch) | /proxy/network/v2/api/site/{site_id}/wireguard/{network_id}/users/batch_delete | POST | JSON body: `[ "user_id_1", "user_id_2", ... ]` | Batch delete by user `_id` values |

## Examples of managing users:

### Add a user:
```bash
$ ./manage-unifi-wg-clients.py -n TestServer -a "Client 101"
Controller: https://unifi.local
Logging in...

Selected network: TestServer (id=6919e3f92bcdc84f083e1cae)
Determining next available interface IP...
Using interface IP: 192.168.7.2
Generating WireGuard keypair...
Creating user 'Client 101'...

User created
+------------+--------------------------+-------------+------------------------+
| Name       | ID                       | IP Address  | Public Key (truncated) |
+------------+--------------------------+-------------+------------------------+
| Client 101 | 691a16a32bcdc84f083e5438 | 192.168.7.2 | d48yUVdbFo3+ElHS...    |
+------------+--------------------------+-------------+------------------------+

Suggested filename: TestServer-Client-101.conf

WireGuard configuration (copy/paste):
[Interface]
PrivateKey = 3RH7NFVEJZRPfrdgu6fBhgml4AHq5ex4/h0VcZs2rDc=
Address = 192.168.7.2/32
DNS = 10.0.0.116, 10.0.0.254

[Peer]
PublicKey = +CXSNgCRLRTvSaKYW7JzpS4Nzg9s0n0bw7ceC8FzFXo=
Endpoint = your.domain.de:51824
AllowedIPs = 192.168.7.0/24, 10.0.0.0/22
PersistentKeepalive = 25
```

### List users
```Bash
$ ./manage-unifi-wg-clients.py -n TestServer -l
Controller: https://unifi.local
Logging in...

Selected network: TestServer (id=6919e3f92bcdc84f083e1cae)

WireGuard users
+---+------------+--------------------------+-------------+
| # | Name       | ID                       | IP Address  |
+---+------------+--------------------------+-------------+
| 1 | Client 101 | 691a16a32bcdc84f083e5438 | 192.168.7.2 |
| 2 | Client 102 | 691a16d52bcdc84f083e545d | 192.168.7.3 |
| 3 | Client 104 | 691a16da2bcdc84f083e5464 | 192.168.7.4 |
| 4 | Client 105 | 691a16de2bcdc84f083e5469 | 192.168.7.5 |
| 5 | Client 106 | 691a16e12bcdc84f083e5470 | 192.168.7.6 |
| 6 | Client 107 | 691a16e52bcdc84f083e547b | 192.168.7.7 |
+---+------------+--------------------------+-------------+
```

### Delete users
#### Via name:
```Bash
$ ./manage-unifi-wg-clients.py -n TestServer -d "Client 102"
Controller: https://unifi.local
Logging in...

Selected network: TestServer (id=6919e3f92bcdc84f083e1cae)

About to delete the following user(s):
+---+------------+--------------------------+-------------+
| # | Name       | ID                       | IP Address  |
+---+------------+--------------------------+-------------+
| 1 | Client 102 | 691a16d52bcdc84f083e545d | 192.168.7.3 |
+---+------------+--------------------------+-------------+
Type 'yes' to confirm deletion of 1 user(s): yes
Deleted 1 user(s) successfully.

Remaining users:

WireGuard users
+---+------------+--------------------------+-------------+
| # | Name       | ID                       | IP Address  |
+---+------------+--------------------------+-------------+
| 1 | Client 101 | 691a16a32bcdc84f083e5438 | 192.168.7.2 |
| 2 | Client 104 | 691a16da2bcdc84f083e5464 | 192.168.7.4 |
| 3 | Client 105 | 691a16de2bcdc84f083e5469 | 192.168.7.5 |
| 4 | Client 106 | 691a16e12bcdc84f083e5470 | 192.168.7.6 |
| 5 | Client 107 | 691a16e52bcdc84f083e547b | 192.168.7.7 |
+---+------------+--------------------------+-------------+
```

#### Via list number:
```Bash
$ ./manage-unifi-wg-clients.py -n TestServer -d
Controller: https://unifi.local
Logging in...

Selected network: TestServer (id=6919e3f92bcdc84f083e1cae)

WireGuard users
+---+------------+--------------------------+-------------+
| # | Name       | ID                       | IP Address  |
+---+------------+--------------------------+-------------+
| 1 | Client 101 | 691a16a32bcdc84f083e5438 | 192.168.7.2 |
| 2 | Client 104 | 691a16da2bcdc84f083e5464 | 192.168.7.4 |
| 3 | Client 105 | 691a16de2bcdc84f083e5469 | 192.168.7.5 |
| 4 | Client 106 | 691a16e12bcdc84f083e5470 | 192.168.7.6 |
| 5 | Client 107 | 691a16e52bcdc84f083e547b | 192.168.7.7 |
+---+------------+--------------------------+-------------+
Select user(s) by number/range/list (e.g., 2-4,6,8): 1-2,3,5

About to delete the following user(s):
+---+------------+--------------------------+-------------+
| # | Name       | ID                       | IP Address  |
+---+------------+--------------------------+-------------+
| 1 | Client 101 | 691a16a32bcdc84f083e5438 | 192.168.7.2 |
| 2 | Client 104 | 691a16da2bcdc84f083e5464 | 192.168.7.4 |
| 3 | Client 105 | 691a16de2bcdc84f083e5469 | 192.168.7.5 |
| 4 | Client 107 | 691a16e52bcdc84f083e547b | 192.168.7.7 |
+---+------------+--------------------------+-------------+
Type 'yes' to confirm deletion of 4 user(s): yes
Deleted 4 user(s) successfully.

Remaining users:

WireGuard users
+---+------------+--------------------------+-------------+
| # | Name       | ID                       | IP Address  |
+---+------------+--------------------------+-------------+
| 1 | Client 106 | 691a16e12bcdc84f083e5470 | 192.168.7.6 |
+---+------------+--------------------------+-------------+
```
