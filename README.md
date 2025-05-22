# Paranoid
Paranoia - "Person and Robot? NO I Didn't!" is simply a point being proven of plagiarism and AI NOT being original work and should be called for what it is.



**Person and robot(?), No I didnt!** is a privacy-focused tool that routes all outbound network traffic through Tor using nftables on Linux. This project is intended as a proof-of-concept to demonstrate that—in contrast to some LLMs that claim 100% credit for their work—real projects are built through collaboration, careful testing, and continuous enhancement. It's a tongue-in-cheek jab at plagiarism in the AI space while providing powerful anonymity features for penetration testers and privacy enthusiasts.

> **Warning:**  
> This project modifies system-level settings (nftables, resolver configurations, and Tor configuration) and should be used only in controlled environments. Improper configuration or misuse might lead to network outages or accidental exposure. Always test thoroughly before deploying in production.

---

## Features

- **Tor Routing with nftables**  
  Routes both IPv4 and IPv6 traffic via Tor to help conceal your source IP.
  
- **Secure DNS Resolution**  
  Optionally orchestrates a local DoH (DNS over HTTPS) resolver by reconfiguring the system’s `/etc/resolv.conf` and updating nftables rules to capture nonstandard DNS ports (including DNS-over-TLS on port 853). A background monitor periodically verifies that DNS queries remain secure, with a choice to either alert you or automatically reapply firewall rules if leaks are detected.

- **Tor Control Integration**  
  Uses a dedicated Go routine to connect to the Tor control port (with optional password authentication) so that identity rotation is handled via Tor’s official control protocol rather than with simple SIGHUP signals.

- **Randomized Identity Rotation**  
  Rotates your Tor identity at randomized intervals around a user-defined base period (default is 30 minutes). This helps prevent pattern detection by adversaries.

- **Ephemeral & Customizable Logging**  
  Choose between local file logging, writing logs to a ramdisk, or encrypted logging. This allows you to minimize forensic footprints depending on your needs.

- **Pluggable Transports for Traffic Obfuscation**  
  Optionally enable pluggable transports (e.g., obfs4) to help camouflage Tor traffic as ordinary HTTPS traffic, reducing the likelihood of detection by network censors or threat hunters.

- **Fail-Safe & Secure Profile Restoration**  
  Saves critical configurations (Tor config, resolver settings, nftables rules) before applying any changes. Upon shutdown or if the application is terminated, the secure profile is restored to return the system to its normal state.

---

## Prerequisites

- **Operating System:** Linux (the code uses Linux-specific build tags)
- **Root Access:** Must be run with superuser privileges (e.g., via `sudo`) due to low-level network configurations.
- **Required Software:**
  - [Tor](https://www.torproject.org/)
  - [nftables](https://wiki.nftables.org/)
  - A local DoH resolver or DNSCrypt service if using secure DNS features.
- **Go Programming Language:** Version 1.16 or newer is recommended.

---

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/MLlolbullen/Paranoid.git
   cd Paranoid
   ```

2. **Build the Project**

   Compile using the Go compiler:

   ```bash
   go build -o paranoid
   ```

3. **Review and Customize (if needed)**

   You may tweak constants (such as ports, CIDRs, or DNS configurations) directly in the source code before building.

---

## Usage

### Starting the Tool

To route traffic through Tor with all enhancements enabled, run:

```bash
sudo ./paranoid -start \
  -dns-resolver \
  -dns-leak-action=reapply \
  -rotate-interval=30m \
  -log-mode=ramdisk \
  -pluggable-transport=obfs4 \
  -tor-control-port=9051 \
  -tor-control=true
```

The above startup will:

- Verify root privileges.
- Save a secure profile of the current Tor, resolver, and nftables configurations.
- Reconfigure `/etc/resolv.conf` (if `-dns-resolver` is enabled) to use a local DNS-over-HTTPS resolver.
- Append a custom fragment (with optional pluggable transport configuration) to your Tor configuration.
- Restart Tor and apply nftables rules.
- Start monitoring for DNS leaks and periodically rotate the Tor identity using a randomized timer based on the provided interval.
- Log all activities to the chosen destination (local, ramdisk, or encrypted log).

### Stopping the Tool

To stop the service (thus flushing nftables rules and restoring original configurations), run:

```bash
sudo ./paranoid -stop
```

This command flushes nftables settings and—if the fail-safe feature is enabled—restores the backed-up configurations.

---

## Enhancements and Customizations

- **Secure DNS Monitoring:**  
  The tool periodically verifies via a secure API endpoint (which you must configure) that DNS lookups are resolving over HTTPS. If a leak is detected, based on your chosen action (`alert` or `reapply`), it will either notify you or automatically reapply the firewall rules.

- **Tor Control Integration:**  
  Instead of simply sending a SIGHUP to force a new Tor circuit, the tool uses the official Tor control protocol. This method is more precise and ensures that the `SIGNAL NEWNYM` command is correctly processed.
  
- **Randomized Rotation:**  
  Avoid timing-based correlation by varying identity rotation intervals around a user-determined base time.

- **Ephemeral Logging & Fail-Safe:**  
  Choose minimal footprint logging modes (e.g., logging to ramdisk) to minimize persistent traces. The fail-safe feature backs up your configuration before making any changes and restores them on shutdown, ensuring that you do not leave your system misconfigured if the tool is unexpectedly terminated.

- **Traffic Obfuscation via Pluggable Transports:**  
  Using obfuscation plugins (such as obfs4) can help disguise Tor traffic as normal HTTPS, adding an extra layer of stealth. This is particularly beneficial for environments where Tor usage might be flagged by network monitoring tools.

---

## Contributing

Contributions, bug reports, and feature suggestions are very welcome! Please file an issue or submit a pull request. Note that this project is as much a statement against claiming 100% credit via LLMs as it is a functional tool—honor and transparency in open-source collaboration is what we value here.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Disclaimer

**Person and robot(?), No I didnt!** modifies system-critical settings (network configurations, firewall rules, and Tor configurations). Use it at your own risk. Always test any changes in a non-production environment and ensure you understand the underlying mechanisms before deploying on critical systems. The authors take no responsibility for any unintended consequences.

---

# Happy anonymizing, and remember: true credit is earned through honest collaboration, not by taking 100% credit with artificial means!

