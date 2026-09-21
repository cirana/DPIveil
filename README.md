# DPIveil

DPIveil is a lightweight Windows command-line network traffic tool written in Python. It combines a temporary Windows DNS policy with WinDivert/PyDivert-based HTTPS strategy selection for Discord connectivity.

## Requirements

- Windows 10/11
- Python 3.10+
- Administrator privileges

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Press `Ctrl+C` to stop DPIveil cleanly.

## DNS policy

The default profile uses Windows-native **NRPT + DoH** for Discord namespaces.

- Resolver: `1.1.1.1`
- DoH template: `https://cloudflare-dns.com/dns-query`
- Plain UDP fallback: disabled
- Adapter DNS settings are not changed
- No local DNS proxy is started
- DNS cache is flushed when the temporary policy is applied and removed
- DPIveil removes only the NRPT rules it created and restores the previous DoH entry state on shutdown

The Discord namespace list is shared by the DNS policy and the active session strategy through `dpiveil/constants.py`, so both layers use the same domain set.

The DNS policy is configured through `profiles/default.json`:

```json
{
  "dns_policy": {
    "enabled": true,
    "resolver": "1.1.1.1",
    "doh_template": "https://cloudflare-dns.com/dns-query",
    "allow_fallback_to_udp": false,
    "domains": [
      "discord.com",
      "discord.gg"
    ]
  }
}
```

The full default domain set is kept in the profile. TLS certificate verification and HSTS are not disabled.

## Automatic HTTPS strategy selection

DPIveil obtains verified Discord IPv4 addresses through DNS-over-HTTPS while retaining normal TLS certificate validation. It then tests the configured candidates in priority order and selects the **first candidate that produces a verified Discord HTTPS response**.

Default candidates:

- `multisplit-2`
- `multidisorder-2`
- `fake-ttl-1`

The selected strategy remains active for the current DPIveil session and is applied to Discord traffic. Discord addresses learned through the active Windows DNS policy are also tracked so the packet engine can protect relevant flows when SNI is unavailable.

The default strategy configuration is in `profiles/default.json`:

```json
{
  "strategy": "auto",
  "strategy_options": {
    "host": "discord.com",
    "timeout": 6,
    "max_ips": 2,
    "candidates": [
      {"name": "multisplit-2", "kind": "multisplit", "priority": 1, "split_pos": 2},
      {"name": "multidisorder-2", "kind": "multidisorder", "priority": 2, "split_pos": 2},
      {"name": "fake-ttl-1", "kind": "fake_ttl", "priority": 3, "ttl": 1}
    ]
  }
}
```

Desktop Discord endpoints are checked after selection for diagnostics. They do not determine which strategy wins.

## Packet engine

The WinDivert engine handles TCP/443 traffic used by the configured HTTPS strategies. It also records inbound SYN-ACK/RST fingerprints and can drop the specific suspect RST pattern observed on protected Discord flows.

DNS is no longer intercepted in the packet engine. Windows handles Discord DNS through the native NRPT + DoH policy described above.

## Project layout

```text
dpiveil/
  app.py          application lifecycle and orchestration
  autoselect.py   verified HTTPS probing and session strategy selection
  constants.py    shared Discord domain constants
  dns_policy.py   temporary Windows NRPT + native DoH policy
  engine.py       WinDivert packet engine
  profiles.py     profile loading
  strategies/     packet manipulation strategies
```

## Tests

Run:

```powershell
python -m unittest discover -s tests
```

Tests cover strategy selection, DNS policy lifecycle/configuration, packet classification and strategy behavior without changing the machine's real DNS configuration.
