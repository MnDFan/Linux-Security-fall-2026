# ECE 

**Major:** Cybersecurity International  
**Academic Year:** 5th year

---

**Course**  
*Linux Security*

**Lab Report**  
LAB 2 – Remote administration and dual-stack network filtering

**Instructor**  
M. BOUSALEM BADRE

**Group Members**  
- ARDILLON Bastian
- PHAN Minh-Duc
- LANQUETIN Octave

**Date**  
October 03, 2026

---
<div style="page-break-after: always;"></div>

## Isolated experimental network

**Q1 : Using Figure 1, explain the purpose of outbound NAT, the absence of an internal gateway and the recovery method if SSH becomes inaccessible**

According to Figure 1, the outbound NAT allows the VMs to get internet and to download software packages and security updates from the Ubuntu repositories, while preventing any unrequested connections from the external network. 
The internal network don't have a gateway to ensure an isolated Layer-2 segment, containing all administrative and filtering tests strictly between the client and the server without routing leaks.
Finally, the hypervisor console grants direct, out-of-band management access to the virtual machines, it acts as an independent fallback recovery mechanism to troubleshoot or restore network and service configurations if SSH access becomes blocked or misconfigured

**P1 : Evidence to retain An annotated topology showing interface names, with extracts of the addresses and the two ping tests**

<div align="center">
  <img src="images\im1.png" alt="" width="500">
  <p><em>Figure 1: Evidence for the P1</em></p>
</div>

## SSH trust and key-based authentication

**Q2 : Distinguish the host key, the user’s public key and the passphrase protecting the user’s private key. Is a fingerprint received over the network, by itself, sufficient to establish trust?**

The host key uniquely identifies and authenticates the SSH server to the client, preventing the Man-in-the-Middle (MitM) attacks. The user's public key is deployed on the server to authenticate the client user's identity without sending passwords over the wire. The passphrase provides local protection by symmetrically encrypting the user's private key stored on the client disk, preventing unauthorized use if the file is stolen.   A fingerprint received over the network is not sufficient by itself to establish trust on first connection with the OTFU model. If an attacker is already performing a MitM attack, they could present their own host key fingerprint over the network. Therefore, trust requires out-of-band verification against a known, authoritative source, such as the hypervisor console

**P2 : Evidence to retain The server’s public fingerprint compared with the console value, followed by successful key-based execution of id over IPv4 and IPv6. Include no private key or passphrase in the report.**

<div align="center">
  <img src="images\im2.png" alt="" width="500">
  <p><em>Figure 2: Public fingerprint of the server</em></p>
</div>

<div align="center">
  <img src="images\im3.png" alt="" width="500">
  <p><em>Figure 3: Comparaison of the public fingerprint</em></p>
</div>

<div align="center">
  <img src="images\im4.png" alt="" width="500">
  <p><em>Figure 4: Sucessful key-based execution of id over IPv4 and IPv6</em></p>
</div>

## SSH server access policy

**Q3 : What do sshd -t, sshd -T -C and a real new connection each demonstrate? Why retain tpexterne as a control with a valid key?**

- sshd -t tests only the syntax and internal consistency of the configuration files without applying changes or testing daemon socket operations.   
- sshd -T -C simulates the daemon's runtime decision engine, evaluating the final, merged configuration directives that will specifically apply to a connection matching the supplied attributes (address, interface, user, port).
- A real new connection demonstrates end-to-end functionality: proper daemon listening, network routing, TCP handshake, cryptographic key exchange, file permissions (.ssh and authorized_keys), and PAM session handling.
- Retaining tpexterne with a valid, installed key serves as a negative control that isolates authorization from authentication. Because the key itself is mathematically valid, the rejection proves that access is denied exclusively by group-level policy (AllowGroups sshadmin) rather than key corruption or absence.

**P3 Evidence to retain Effective IPv4/IPv6 values and a table of four results: two legitimate accesses, password authentication rejected, and an account outside the group rejected; two log extracts are sufficient.**

<div align="center">
  <img src="images\im5.png" alt="" width="500">
  <p><em>Figure 5: Result for the P3</em></p>
</div>

## IPv4 and IPv6 filtering with nftables

**Q4 : Predict the results for .20, .30, ::20 and ::30. What failure could a blanket block on ICMPv6 cause, even if TCP 22 were permitted?**

Connections from 10.77.0.20 and fd42:77::20 will match the explicit rules with counters and establish a TCP connection to port 22. Conversely, connections from 10.77.0.30 and fd42:77::30 will miss these rules, hit the default input drop policy (counter drop), and time out without any TCP response.

Unlike IPv4, ICMPv6 is mandatory for core network operation. A blanket block disables the Neighbor Discovery Protocol (NDP) (Neighbor Solicitations and Advertisements), preventing the client and server from resolving each other's link-layer addresses. Without NDP, the machines cannot communicate at all over IPv6, breaking SSH even if port 22 is permitted. It also breaks Path MTU Discovery (PMTUD), causing large packets to be dropped silently.

## Validation of filtering decisions

**Q5 : How can you distinguish a network filter decision from an SSH authentication rejection? Give two complementary observations, rather than relying solely on the client message.**

Firewall counters and packet behavior: A network filter drop discards packets silently at the IP layer, preventing the TCP 3-way handshake from completing and incrementing the server's counter drop rule in nftables. In contrast, an SSH authentication rejection completes the TCP handshake, increments the firewall's port 22 accept rule counter, and exchanges protocol messages.   

Daemon logs in systemd journal: A connection blocked by the network filter never reaches the SSH daemon, leaving no trace in journalctl -u ssh.service. An authentication rejection reaches userspace and triggers explicit audit logs from sshd documenting the rejection cause (e.g., unauthorized group or invalid authentication method).

**P4 : Evidence to retain A matrix of the four sources and TCP results, two SSH identities, counters and an outbound NAT check. Reuse this same table in the report.**

<div align="center">
  <img src="images\im6.png" alt="" width="500">
  <p><em>Figure 6: Result for the P4</em></p>
</div>

## Detection and automated response with Fail2ban

**Q6 : Read Figure 2: why does a valid key fail to bypass a ban? Why must the client address not be included in ignoreip for this experiment?**

- **maxretry**: The maximum number of failed authentication attempts permitted from a single IP address before Fail2ban triggers a ban action (set to 3).
- **findtime**: The sliding time window during which the failed attempts are counted (set to 10 minutes). If the count reaches maxretry within this window, the ban is enacted.
- **bantime**: The duration for which the offending IP address is blocked and denied access by firewall rules before being automatically unbanned (set to 10 minutes).

Preference for the systemd backend: Modern Linux distributions handle system events through systemd-journald. Using backend = systemd allows Fail2ban to query structured binary logs directly in-memory via the Journal API without relying on flat files like /var/log/auth.log. This avoids file-polling race conditions, eliminates issues caused by logrotate truncating files, reduces disk I/O, and provides tamper-resistant, authenticated log records with precise metadata.

## Ban analysis and access restoration

**Q7 : What limitations remain if several users share a NAT address or an authorised source is compromised? Does Fail2ban’s active status alone demonstrate the behaviour observed?**

- Detection: On the 3rd failed authentication attempt, sshd writes a rejection record to systemd-journald. Fail2ban, continuously monitoring the journal stream via its systemd backend, parses the failure pattern and increments the failure counter for 10.77.0.20 to reach maxretry = 3 within the findtime window.
- Ban action: Fail2ban triggers the action defined in banaction = nftables-multiport, calling the nft binary to add 10.77.0.20 to the set or input chain managed by Fail2ban (with priority higher than the base accept rule).   Packet drop: Any subsequent TCP SYN packet from 10.77.0.20 directed at port 22 matches the Fail2ban drop rule and is discarded before reaching the OpenSSH socket.
- Immediate restoration: Running fail2ban-client unban immediately removes the IP address element from the kernel's nftables set or chain. Because nftables evaluates rules dynamically in real time without requiring a daemon restart or connection reload, valid packets immediately fall through to the base allow rule for 10.77.0.20 on port 22. 

**P5 : Evidence to retain A short timeline: event, counter/banned address, rejection of the legitimate account, continued IPv6 access, then success after the ban is lifted.**

<div align="center">
  <img src="images\im7.png" alt="" width="500">
  <p><em>Figure 7: Result for the P5</em></p>
</div>

## Independent task on temporary access

---

END