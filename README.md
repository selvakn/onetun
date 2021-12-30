# wg-port-forward

A cross-platform, user-space WireGuard port-forwarder (to expose local services to a wireguard network) that requires no system network configurations.

## Use-case

- You have an existing WireGuard endpoint (router), accessible using its UDP endpoint (typically port 51820); and
- You have a service (only TCP for now) on a port accessible locally and
- You want to expose this service to the wireguard peer (or other peers connected to it) without installing wireguard systemwide (without tun/tap or kernel module)

For example, this can be useful for exposing local service during development of the service

## Usage

```
./wg-port-forward  --ports-to-forward <port> [<ports>]                    \
    --endpoint-addr <public WireGuard endpoint address>                   \
    --endpoint-public-key <the public key of the peer on the endpoint>    \
    --private-key <private key assigned to wg-port-forward>               \
    --source-peer-ip <IP assigned to wg-port-forward>                     \
    --keep-alive <optional persistent keep-alive in seconds>
```

### Example

Suppose your WireGuard endpoint has the following configuration, and is accessible from `a.b.c.d:51820`:

```
# /etc/wireguard/wg0.conf

[Interface]
PrivateKey = ********************************************
ListenPort = 51820
Address = 192.168.4.1

# A friendly peer that wants to reach the TCP service on your local
[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AllowedIPs = 192.168.4.2/32

# Peer assigned to wg-port-forward (local)
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
AllowedIPs = 192.168.4.3/32
```

We can use **wg-port-forward** to expose the local ports , say `127.0.0.1:8080`, that will tunnel through WireGuard and made available to other peers:

```shell
./wg-port-forward --ports-to-forward 8080 [2222]                          \
    --endpoint-addr a.b.c.d:51820                                         \
    --endpoint-public-key 'PUB_****************************************'  \
    --private-key 'PRIV_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'          \
    --source-peer-ip 192.168.4.3                                          \
    --keep-alive 10
```



## Architecture

wg-port-forward uses [boringtun](https://github.com/cloudflare/boringtun), [tokio](https://github.com/tokio-rs/tokio), [smoltcp](https://github.com/smoltcp-rs/smoltcp) and heavily inspired from [onetun](https://github.com/aramperes/onetun).
Special thanks to the developers of those libraries.

### UDP

UDP is not supported at the moment. Might come in the future.

## License

MIT. See `LICENSE` for details.
