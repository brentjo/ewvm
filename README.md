## EWVM

Quickly create ephemeral Wireguard-enabled VMs on DigitalOcean for various testing purposes. Not a formal project I intend to maintain, and I don't recommend you use this, but maybe you'll find what's being done here interesting.

<img src="https://github.com/brentjo/ewvm/assets/6415223/928dd21a-d582-446d-9d23-57b254abb34f" height="400">

**Example use cases**

- A temporary VPN to have an IP address to proxy traffic through. Maybe you don’t need a VPN running 24/7 racking up a bill, but occasionally do need a second IP address for testing or debugging purposes, and this tooling enables you to quickly spin a VPN up temporarily. This was the original purpose of this tooling.
  - `ewvm up` to bring a Wireguard-enabled machine up. Prints out a QR code to easily connect from your phone via the Wireguard mobile app, and a `wg-quick` command to connect from the machine running the tooling.  
- A public HTTP receiver to easily test webhooks and similar
    - `ewvm log` to listen on a port and print out received TCP traffic, or provide the `--tunnel` flag to additionally spawn a Cloudflare Tunnel so that you can receive traffic with a domain name / TLS-enabled endpoint.
- A throwaway-VM to run potentially untrusted code on and discard, for those one-off scripts and tools with risky origins that you are not comfortable running on your personal machine.
    - `ewvm ssh` to interactively SSH into the VM and do whatever you’d like
    - As a caveat: you may only want to use it for this purpose if you have no other resources on your DigitalOcean account. I’m unfamiliar with how ‘isolated by default’ new VMs are — for example I see it noted that all VMs created in the same region will be members of the same private VPC network by default and have connectivity to each other, so depending on how/what services you have running on existing machines, that may be problematic.

### Installation

Download and install Go if you do not already have it: https://go.dev/doc/install

```
git clone https://github.com/brentjo/ewvm && cd ewvm && go build
```

`./ewvm` to run the binary out of the project's directory, or copy the binary to wherever you'd like in your `$PATH` for global use in your terminal.

### Uninstallation

Run the command: `ewvm uninstall`

This will destroy all VMs, SSH keys, config directories, and keychain entries associated with this tooling. Notably, it does not revoke the DigitalOcean API key you provided for the tooling, so be sure to revoke it if it's no longer needed.

To manually clean up:
- Delete the `$HOME/.ewvm` directory. This is where all config files and logs are stored. 
- Delete the keychain entries: `EWVM: DigitalOcean API token`, `EWVM: Private SSH key`, `EWVM: Public SSH key`
- Delete the SSH key on your DigitalOcean account named `ephemeral-wg-key`
  - https://cloud.digitalocean.com/account/security
- Delete any VMs on your DigitalOcean account with the tag `ewvm-temporary-machine`
  - https://cloud.digitalocean.com/droplets
- Revoke the API key you provided for this tooling
  - https://cloud.digitalocean.com/account/api/tokens
