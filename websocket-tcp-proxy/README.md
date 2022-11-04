# websocket-tcp-proxy

turn incoming websocket connections into bi-directional tcp streams

it's websockify but with the client gets to pick what tcp address to connect to, basically

## How to test

You'll want `netcat` and [`websocat`](https://github.com/vi/websocat) installed.

Terminal 1:

```
RUST_LOG=debug cargo run
```

Terminal 2:

mac
```
netcat -l 127.0.0.1 -p 3000
```

linux
```
nc -l 127.0.0.1 3000
```

Terminal 3:

```
websocat -b ws://127.0.0.1:3001/v1/127_0_0_1/3000
```

Now you can type in the `websocat` terminal and you should see text on the netcat terminal, and type in the `netcat` terminal and it should show in the websocat terminal.

## Further reading

websocat seems to have a really slick websocket <-> tcp thingy, it's just a little hard to read:
https://github.com/vi/websocat/blob/6d0e23cbedd1e3b9377cf0efdf9eef260d9d5ae2/src/net_peer.rs

this guy did all the work for me basically just referencing and modifying as needed:
https://github.com/HsuJv/axum-websockify
