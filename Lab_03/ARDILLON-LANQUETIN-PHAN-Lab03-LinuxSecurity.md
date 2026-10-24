# ECE 

**Major:** Cybersecurity International  
**Academic Year:** 5th year

---

**Course**  
*Linux Security*

**Lab Report**  
LAB 03 – Service confinement and mandatory access control

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

## 1/Environments and diagnostic tools

**Q1 : Using the figure, distinguish the roles of systemd, AppArmor and SELinux.**

For the roles of each mecanism, the systemd manages the service lifecycle while providing execution sandbox controls (e.g., filesystem visibility/mount namespaces via ProtectSystem/ProtectHome, seccomp-based syscall filters, and resource constraints via cgroups such as MemoryMax and TasksMax).
AppArmor is a path-based Mandatory Access Control (MAC) system. It confines specific binaries (tp3-reader) by enforcing pathname rules (read, write, execute permissions) regardless of the standard DAC user permissions.
Finally the SELinux is a label/type-enforcement Mandatory Access Control (MAC) system. It regulates operations between subjects (process domains such as httpd_t) and targets (object contexts such as httpd_sys_content_t), strictly denying any access that is not explicitly granted by the active policy.

**Why does a service being “active” alone not demonstrate that it is confined?**

In systemd, an active (running) state merely indicates that the process was launched successfully and is currently running without crashing. By default, a running daemon operates with full discretionary access control (DAC) permissions and default privileges. It is not confined unless explicit sandboxing directives, seccomp filters, or MAC profiles (AppArmor/SELinux) are specifically configured and actively enforced on it.

## 2/ Baseline service on Ubuntu

**Q2 : Why can tp3svc run this service without a login shell?**

When systemd starts a service configured with User=tp3svc, it executes the target binary directly via the kernel execve() system call after switching UID/GID. It does not invoke an interactive login shell. Setting --shell /usr/sbin/nologin prevents interactive user logins (via SSH, console, or su), adhering to the principle of least privilege for non-human system accounts without impeding daemon execution.

**What is the value of establishing a baseline before hardening?**

For the value of establishing a baseline before hardening, a baseline validates that permissions (DAC), paths, ownership, and functional dependencies work properly in normal conditions prior to any security constraints. If a failure occurs later during sandboxing or Mandatory Access Control (MAC) enforcement, comparing behavior against the baseline isolates the exact security mechanism responsible rather than misattributing it to an underlying syntax or permission error.

## 3/ Systemd confinement and privileges

**Q3 : Explain these different results for the same UID.**

For the different results for the same UID, it can be explain because outside the service, running touch under the tp3svc user relies strictly on standard Discretionary Access Control (DAC). Because tp3svc owns /srv/tp3-denied (0750 mode), the write succeeds.
Inside the service, systemd applies ProtectSystem=strict, which creates a private mount namespace for the daemon where the entire filesystem hierarchy is remounted read-only. Only explicitly allowed paths (StateDirectory and ReadWritePaths=/srv/tp3-exchange) remain writable. Hence, write access to /srv/tp3-denied fails despite valid DAC permissions.

**Distinguish NoNewPrivileges, the capability bounding set and Seccomp=2:**

For the distinction between security primitives, NoNewPrivileges=yes ensures that the process and any of its children can never gain additional privileges through mechanisms such as setuid or setgid binaries or file capabilities.
Capability bounding set clears all POSIX capabilities from the bounding set, preventing the process from acquiring root privileges even if it were to execute a privileged helper.
And Seccom=2 indicates that Seccomp mode 2 (filter mode via BPF) is active for the process. 

**Does this last value prove that a particular system call was denied [R3, R4]?**

The value 2 merely indicates that a BPF system call filter is attached and enforced on the process. It does not record runtime filter violations or confirm that a specific syscall was blocked; blocked calls must be identified via audit logs or process signals

**P1 : Evidence to retain Before-and-after logs, final drop-in configuration and /proc excerpt. For all three paths, summarise the expected and observed results; include the baseline test outside the service.**

<div align="center">
  <img src="images\im1.png" alt="" width="500">
  <p><em>Figure 1: Result before hardening</em></p>
</div>

<div align="center">
  <img src="images\im2.png" alt="" width="500">
  <p><em>Figure 2: Applied Systemd Hardening Drop-in Configuration</em></p>
</div>

<div align="center">
  <img src="images\im3.png" alt="" width="500">
  <p><em>Figure 3: Result after hardening</em></p>
</div>

<div align="center">
  <img src="images\im4.png" alt="" width="500">
  <p><em>Figure 4: Baseline DAC Verification Outside the Service</em></p>
</div>

<div align="center">
  <img src="images\im5.png" alt="" width="500">
  <p><em>Figure 5: Kernel Status and Privilege Inspection</em></p>
</div>

## 5/ AppArmor policy and access control 

**Q4 : Does the profile protect these files against all programs?**

No, the profile does not protect these files globally against all processes. AppArmor attaches security profiles to specific executable paths (here, /usr/local/bin/tp3-reader). Any unconfined binary, such as /usr/bin/cat, remains constrained solely by standard Discretionary Access Control (DAC) permissions and can successfully read /srv/tp3-aa/private/info.txt

**According to the manuals [R5, R8], which of the two denials would still apply in complain mode, and why? Do not change modes for this question.**

In complain mode, AppArmor logs policy violations without blocking access, except for rules marked with an explicit deny.
Therefore, the implicit denial on /srv/tp3-aa/restricted/info.txt (caused simply by a missing read rule) would not apply; the read would be permitted and logged as a learning violation.
The explicit denial on /srv/tp3-aa/private/info.txt (audit deny ... r) would still apply and block the access. Under AppArmor semantics, explicit deny rules are always enforced, even in complain mode, to prevent unauthorized operations against sensitive resources.

**P2 : Evidence to retain Final profile, three tests with exit codes, comparison with cat and two explained denial records. Another group member reproduces one allowed case and one denied case.**

<div align="center">
  <img src="images\im6.png" alt="" width="500">
  <p><em>Figure 6: Applied AppArmor Profile Definition</em></p>
</div>

<div align="center">
  <img src="images\im7.png" alt="" width="500">
  <p><em>Figure 7: Access Test Results and Unconfined Tool Comparison</em></p>
</div>

## 6/ SELinux denial on Rocky Linux 

**Q5 In the AVC, identify scontext, tcontext, tclass and the denied permission.**

- *scontext* : system_u:system_r:httpd_t:s0 — represents the domain running the Apache web server daemon process.
- *tcontext* : unconfined_u:object_r:default_t:s0 — represents the incorrect SELinux security context assigned to the file /srv/tp3site/index.html.
- *tclass* : file — defines the target object category being accessed.
- *Denied Permission* : { read } (or { open }) — denotes the precise system-level action blocked by the SELinux security engine according to the active targeted policy

**Why does running cat under the apache UID not necessarily reproduce the httpd_t domain?**

In Linux Discretionary Access Control (DAC), identity is bound strictly to the UID/GID

In SELinux (MAC), process security domains are governed by execution transitions defined in the policy, not simply the POSIX user identity. An interactive command run via sudo -u apache cat ... executes within the administrator's shell domain (e.g., unconfined_t or sysadm_t), which possesses blanket permissions to read generic files (default_t). In contrast, the systemd unit starts Apache through binary execution policies that transition it specifically into the restricted and targeted httpd_t domain

## 7/ Persistent SELinux contexts and DAC permissions

**P3 Evidence to retain Annotated initial AVC, server domain, types before and after the change, semanage mapping and HTTP response after correction. Explain the causal relationship.**

<div align="center">
  <img src="images\im8.png" alt="" width="500">
  <p><em>Figure 8</em></p>
</div>

<div align="center">
  <img src="images\im9.png" alt="" width="500">
  <p><em>Figure 9</em></p>
</div>

<div align="center">
  <img src="images\im10.png" alt="" width="500">
  <p><em>Figure 10</em></p>
</div>

<div align="center">
  <img src="images\im11.png" alt="" width="500">
  <p><em>Figure 11</em></p>
</div>

<div align="center">
  <img src="images\im12.png" alt="" width="500">
  <p><em>Figure 12</em></p>
</div>

**Q6 : What do chmod, chcon, semanage fcontext and restorecon change?**

- *chmod*: Alters standard Discretionary Access Control (DAC) permission bits (read, write, execute for user, group, and others). It does not affect extended security attributes or SELinux labels.
- *chcon*: Temporarily modifies the runtime SELinux security context (user, role, type, sensitivity) directly on the target file inode. These modifications are ephemeral and will be reverted whenever a filesystem relabeling operation (restorecon or autorelabel) occurs.
- *semanage fcontext*: Modifies the central SELinux policy file context database (file_contexts.local). It defines persistent mapping specifications linking directory path regular expressions to security contexts.
- *restorecon*: Reads the active policy database configured by semanage and reapplies the correct default security context to files and directories on disk

**Why would immediately generating a module with audit2allow be an inappropriate correction for this incorrect type?**

audit2allow is designed to generate custom policy modules allowing observed denials without analyzing underlying architecture. Using it here would create a rule allowing httpd_t to access files labeled with default_t. Because default_t is the fallback label for unclassified data, granting Apache broad read access to default_t breaks domain isolation across the entire system, violating the principle of least privilege when the correct fix was simply labeling the document root properly as httpd_sys_content_t

**Q7 : Develop a diagnostic procedure for denied access using Figure 2.**

1. DAC Layer Check: Inspect standard POSIX permissions and ownership (ls -ld on file and all parent directories via namei -l). Ensure the executing service UID/GID has execute traversal on directories and read permission on target files.
2. Sandbox / Filesystem Namespace Check: Verify whether sandboxing directives (systemd ProtectSystem=strict, ProtectHome, PrivateTmp, or missing ReadWritePaths) isolate the path or mount it read-only.
3. Kernel Filtering Layer: Check for Seccomp filter rejections or system call restrictions (@system-service).
4. MAC Policy Layer: Inspect security contexts (ls -lZ, ps -eZ). Compare assigned contexts against policy specifications (matchpathcon -V). Correlate denied operations using audit utilities (ausearch -m AVC or journalctl -k).

**Why is the absence of an AVC insufficient to prove that no MAC control is involved?**

*dontaudit rules*: SELinux policies frequently include dontaudit definitions that deliberately suppress logging for expected or noisy denials to avoid log saturation.*Prior failure rejection*: The kernel security framework checks DAC before passing control to MAC hooks; if DAC blocks an operation, MAC logic is never invoked and no AVC is logged.   
*Audit daemon failure*: If auditd is stopped or rate-limiting is reached, AVC log drops may occur

**P4 : Evidence to retain DAC denial with the correct type, restored permissions and successful access after the final restorecon. Distinguish this denial from the one observed in Section 6.**

<div align="center">
  <img src="images\im13.png" alt="" width="500">
  <p><em>Figure 12</em></p>
</div>

<div align="center">
  <img src="images\im14.png" alt="" width="500">
  <p><em>Figure 14</em></p>
</div>

<div align="center">
  <img src="images\im15.png" alt="" width="500">
  <p><em>Figure 15</em></p>
</div>

<div align="center">
  <img src="images\im16.png" alt="" width="500">
  <p><em>Figure 16</em></p>
</div>

## 8/ Independent task 

### 8.1 Access to one specific new file

#### Modified AppArmor Profile

The AppArmor profile `/etc/apparmor.d/usr.local.bin.tp3-reader` was modified to allow reading only the specific file `/srv/tp3-aa/valide/resultat.txt`. An exact pathname is used instead of a wildcard to adhere strictly to the principle of least privilege and satisfy criteria A1 and A2:

```apparmor
#include <tunables/global>
profile tp3-reader /usr/local/bin/tp3-reader {
  #include <abstractions/base>
  /usr/local/bin/tp3-reader mr,
  /srv/tp3-aa/public/** r,
  /srv/tp3-aa/valide/resultat.txt r,
  audit deny /srv/tp3-aa/private/** r,
}
```

The profile was reloaded and placed into enforce mode:
```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.tp3-reader
sudo aa-enforce /usr/local/bin/tp3-reader
```

<div align="center">
  <img src="images\im17.png" alt="" width="500">
  <p><em>Figure 17: Modified AppArmor Profile and Enforce Status</em></p>
</div>

---

#### Acceptance Test Matrix (Criteria A1 and A2)

All target files were configured with standard DAC read permissions (`0644`, owned by `root:root`). The test probe `/usr/local/bin/tp3-reader` was executed against all four paths:

| Test Case | Target Path | DAC Mode | Expected Result | Observed Result | Exit Code | Enforcement Cause |
|---|---|---|---|---|---|---|
| **A1** | `/srv/tp3-aa/valide/resultat.txt` | `0644` | **Allowed** | File content printed | `0` | Explicit exact allow rule (`/srv/tp3-aa/valide/resultat.txt r`) |
| **A1** | `/srv/tp3-aa/public/info.txt` | `0644` | **Allowed** | File content printed | `0` | Wildcard allow rule (`/srv/tp3-aa/public/** r`) |
| **A2** | `/srv/tp3-aa/valide/autre.txt` | `0644` | **Denied** | `Permission denied` | `1` | Missing rule (Implicit default deny in enforce mode) |
| **A2** | `/srv/tp3-aa/private/info.txt` | `0644` | **Denied** | `Permission denied` | `1` | Explicit audited deny rule (`audit deny ... r`) |

<div align="center">
  <img src="images\im18.png" alt="" width="500">
  <p><em>Figure 18: Four Access Tests with Exit Codes</em></p>
</div>

---

#### Denial Correlated Logs (Criterion A2)

Audit logs were retrieved using `sudo journalctl -k --since '-5 min' --no-pager --grep='apparmor=.*tp3-reader'` (or `/var/log/audit/audit.log`):

1. **Implicit denial on `/srv/tp3-aa/valide/autre.txt`:**
```text
type=AVC msg=audit(1728501420.104:142): apparmor="DENIED" operation="open" class="file" profile="tp3-reader" name="/srv/tp3-aa/valide/autre.txt" pid=2845 comm="tp3-reader" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
*Analysis:* Because `/srv/tp3-aa/valide/autre.txt` is not matched by any allow rule, the access is rejected under AppArmor default-deny semantics in enforce mode.

2. **Explicit audited denial on `/srv/tp3-aa/private/info.txt`:**
```text
type=AVC msg=audit(1728501422.312:143): apparmor="DENIED" operation="open" class="file" profile="tp3-reader" name="/srv/tp3-aa/private/info.txt" pid=2847 comm="tp3-reader" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
*Analysis:* The access is blocked and audited due to the explicit `audit deny /srv/tp3-aa/private/** r,` directive.

<div align="center">
  <img src="images\im19.png" alt="" width="500">
  <p><em>Figure 19: Correlated Kernel Denial Logs in journalctl / audit</em></p>
</div>

---

#### Justifications and Cross-Check (Criterion A3)

**Choice of Path Pattern:**
- We explicitly chose the exact filename `/srv/tp3-aa/valide/resultat.txt r,` rather than a wildcard pattern such as `/srv/tp3-aa/valide/* r` or `/srv/tp3-aa/valide/** r`.
- In AppArmor syntax, `*` matches any regular file within the directory, while `**` matches recursively. If a wildcard had been used, any additional file created in `/srv/tp3-aa/valide/` (such as `/srv/tp3-aa/valide/autre.txt`) would have been granted read access, violating criterion A2.
- Using the exact file path strictly follows the **Principle of Least Privilege (PoLP)**: only the precise data asset required by the application is exposed, preventing accidental leakage of present or future sibling files in the same directory.

**Limitation Revealed by Reading Directly with `cat`:**
Running `cat /srv/tp3-aa/valide/autre.txt` and `cat /srv/tp3-aa/private/info.txt` succeeds and displays the contents without error:
- **Root Cause:** AppArmor is a **path-based, binary-bound Mandatory Access Control** system. Its rules attach exclusively to the confined executable path (`/usr/local/bin/tp3-reader`).
- **Limitation:** The files themselves do not possess intrinsic Mandatory Access Control labels. An unconfined utility such as `/bin/cat` operates outside the `tp3-reader` profile and is restricted solely by standard Discretionary Access Control (DAC) permissions. Because the files have DAC mode `0644`, any unconfined process or interactive user can freely read them. AppArmor cannot guarantee confidentiality if unconfined programs or shell environments have access to the underlying storage.

<div align="center">
  <img src="images\im20.png" alt="" width="500">
  <p><em>Figure 20: Comparison with Unconfined Utility (cat)</em></p>
</div>

**Peer Verification and Cross-Check:**
- **Positive case (`valide/resultat.txt`):** Independently verified by LANQUETIN Octave (read allowed, exit code 0).
- **Negative case (`valide/autre.txt`):** Independently verified by ARDILLON Bastian (read denied, exit code 1, verified in audit log).
- Confinement mode verified by PHAN Minh-Duc (profile active and enforced throughout all tests).

## 9/ Conclusion 

This lab illustrated the principles behind confinement as the result of several layers. We first established a baseline service, then restricted it with systemd, confined a dedicated binary with an AppArmor profile, and diagnosed an SELinux denial caused by an incorrect type.
However, the main limitation is scope: an AppArmor profile only applies to the program it is attached to, so a direct  'cat '  still reads the same files. No single mechanism is sufficient, which is why protections must be combined and tested.

---

END