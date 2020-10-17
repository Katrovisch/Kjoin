<h1 align="center">Kjoin</h1>
<h4 align="center"><code>Assistant for Joining Linux Machines to Active Directory.</code></h4>

- **Verification**
  - Check machine time synchronization with domain.
  - Configure DNS and domain search.
  - Check domain name resolution.

- **Systems Tested**
  - Fedora 31
  - Linux Mint 19.3
  - Ubuntu 18.04
  - CentOS 8
  - Debian 10
  
- **Depedencies**
  - `dialog`
  - `whiptail`
  - `newt` (Fedora)
  - `dnsutils` (Debian-Based)
  - `bind-utils` (RHEL/Fedora)

- **Usage**
```
# chmod +x Kjoin.sh
# ./Kjoin
```

- **License**

Kjoin is licensed under the [GNU General Public License v3.0](https://github.com/Katrovisch/Kjoin/blob/master/LICENSE)
