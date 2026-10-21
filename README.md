# udpdup — 2-leg packet duplication / de-dup for SRT

```
           pcA                                          pcB
 SRT caller ──udp──► udpdup ══ nicA1 ─ leg1 ─ nicB1 ══► udpdup ──udp──► SRT listener
 (encoder)  127.0.0.1:6000  ══ nicA2 ─ leg2 ─ nicB2 ══►        127.0.0.1:9000 (decoder)
```

Every UDP datagram from the local SRT app gets a 16-byte header (session id + 64-bit
sequence number) and is sent on **both** legs. The far end keeps the first copy that
arrives, drops the second one, and passes the original datagram on to its local app.
This works in both directions, so SRT's ACK/NAK/keepalive return traffic is covered
too. SRT never sees the duplication; to SRT it looks like one path with only the
loss that happened on both legs at once.

## Build (on both PCs)

```
gcc -O2 -Wall -o udpdup udpdup.c
```

## Example addressing

| leg  | pcA            | pcB            |
|------|----------------|----------------|
| leg1 | nicA1 10.0.1.1 | nicB1 10.0.1.2 |
| leg2 | nicA2 10.0.2.1 | nicB2 10.0.2.2 |

Put each leg on its own subnet so the kernel sends each socket out of the right NIC.
If you can't, add `,dev=<iface>` to the `--leg` option. That uses `SO_BINDTODEVICE`,
which needs root or CAP_NET_RAW.

## Run

**pcB (receiver):**
```
./udpdup --local-connect 127.0.0.1:9000 \
  --leg 10.0.1.2:7001,10.0.1.1:7001 \
  --leg 10.0.2.2:7002,10.0.2.1:7002

srt-live-transmit "srt://:9000?mode=listener&latency=500" udp://127.0.0.1:5001
#   or: ffmpeg -i "srt://127.0.0.1:9000?mode=listener" ...
```

**pcA (sender):**
```
./udpdup --local-listen 127.0.0.1:6000 \
  --leg 10.0.1.1:7001,10.0.1.2:7001 \
  --leg 10.0.2.1:7002,10.0.2.2:7002

ffmpeg ... -f mpegts "srt://127.0.0.1:6000?mode=caller&latency=500&pkt_size=1316"
```

Notes:
- The SRT caller has to be on the `--local-listen` side. The `--local-connect` side
  forwards to a fixed address, so the SRT listener goes there. If you want the
  roles the other way round (pcB calls and pcA listens), swap `--local-listen` and
  `--local-connect` between the two PCs.
- Open UDP 7001/7002 in the firewall on both PCs.
- Overhead is 16 bytes per packet: a 1316-byte TS payload becomes about 1376 bytes
  of UDP payload, well under a 1500 MTU.
- The de-dup window is 65,536 packets per direction, about 6 s at 100 Mbps. A
  restarted peer is detected by its new session id, and the window resets.
- Set the SRT `latency` above the leg RTT plus the delay difference between the
  legs. SRT only has to retransmit packets lost on **both** legs.
- Counters go to stderr every 10 s (`--stats N`). On each leg, `new` counts packets
  that arrived first on that leg and `dup` counts the redundant copies. If one
  leg's `rx` stops climbing, that leg is down.
- `,loss=PCT` on a `--leg` drops that percentage of outgoing packets on purpose,
  for testing.

## Tested (loopback, 6 Mbps H.264 TS, SRT latency 500 ms)

| leg loss (simulated) | result |
|---|---|
| 0% / 0%     | baseline |
| 20% / 20%   | about 4% residual loss reaches SRT, all of it recovered, output same as baseline |
| 100% / 0%   | output same as baseline (leg1 dead) |
| 0% / 100%   | output same as baseline (leg2 dead) |

## Alternative: native SRT bonding

libsrt 1.5.x has socket groups. `type=broadcast` does the same duplicate-and-de-dup
inside SRT itself. However, `srt-live-transmit` and ffmpeg do not expose groups.
You need `srt-test-live` built with `-DENABLE_BONDING=ON`, or your own app that
uses `srt_create_group()`. udpdup works with any SRT app, unmodified.
