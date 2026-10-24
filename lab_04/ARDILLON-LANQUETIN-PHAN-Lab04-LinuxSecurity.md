# ECE 

**Major:** Cybersecurity International  
**Academic Year:** 5th year

---

**Course**  
*Linux Security*

**Lab Report**  
LAB 04 – Linux Security

**Instructor**  
M. BOUSALEM BADRE

**Group Members**  
- ARDILLON Bastian
- PHAN Minh-Duc
- LANQUETIN Octave

**Date**  
October 24, 2026

---
<div style="page-break-after: always;"></div>

## 1/Environment and integrity verification

**Q1 A person can replace both resultat.txt and resultat.sha256. Which property is then missing from the check? Suggest an independent way to establish trust in the reference.**

The check lacks authenticity and non-repudiation. While a cryptographic hash ensures integrity, as it confirms that the document matches the computed digest, it doesn't authenticate the author or provenance of that digest. This means that an adversary capable of altering resultat.txt can simply recompute and overwrite resultat.sha256 with the new hash, bypassing detection completely.

To establish trust in the reference digest independently, we can use an independent out-of-band channel that would transmit or verify the hash value through a separate medium. We could also apply digital signatures to cryptographically sign the digest using a private key belonging to a trusted identity, whose public key fingerprint is independently authenticated before verification

**P1 Evidence to retain Briefly identify the environment and retain the three verification results: original accepted, modification rejected, restored original accepted. Reuse these excerpts for Q1.**

<div align="center">
  <img src="images\im1.png" alt="" width="500">
  <p><em>Figure 1: Evidence for P1</em></p>
</div>

## 2/Digital signatures and trusted keys

**Q2 Why is a valid signature made with an unknown public key insufficient to authenticate the Atlas laboratory?** 

A valid signature only proves that the document was signed by the private key matching the supplied public key, and that the data has not been altered since signing. However, without an authenticated link between the public key and the identity of the Atlas laboratory, anyone can generate their own key pair, sign an arbitrary document, and claim to be Atlas. Authenticity relies entirely on trusting that the public key belongs to the legitimate entity.

**What changes if the private key is compromised?**

If the private key is compromised, the non-repudiation and authenticity guarantees are completely broken. An attacker holding the private key can forge arbitrary documents or alter existing ones and produce signatures that are cryptographically valid against the legitimate public key. Any past or future signatures produced by that key can no longer be trusted

**P2 Evidence to retain Approved public-key fingerprint and channel used; permissions of signer.key without its contents; successful verification of the original and rejection of the modified document.**

The public-key fingerprint (18e7f7364...) was compared and validated out-of-band verbally in person between team members.

<div align="center">
  <img src="images\im2.png" alt="" width="500">
  <p><em>Figure 2: Evidence for P2</em></p>
</div>

## 3/Creation of a LUKS2 volume

**Q3 At which layer in the figure does encryption occur?** 

Encryption occurs at the block device layer (dm-crypt / loop device), between the filesystem (ext4) and the underlying storage (coffre.img). The kernel transparently encrypts data written to /dev/mapper/tp4_coffre before storing it in coffre.img, and decrypts data read from the image.

**Why can root read the mounted file despite LUKS?** 

Once the volume is unlocked with the passphrase and mounted, the cleartext block device (/dev/mapper/tp4_coffre) is exposed to the operating system. At that stage, standard OS access controls apply. Since the root superuser bypasses standard Unix discretionary access controls (DAC), it can read any file within the mounted filesystem. LUKS protects data at rest (offline), not against a privileged user on a live, running system where the volume is already mounted.

**Compare the threat addressed by LUKS with the threat addressed by Unix permissions.**

- LUKS (Encryption at rest): Protects against physical or offline threats—such as device theft, unauthorized disk cloning, or reading data by booting another OS/inspecting raw image blocks.
- Unix permissions (Access control on a running system): Protect against unauthorized access by distinct local users and unprivileged processes while the system is running and the data is mounted.

## 4/Volume locking and metadata protection

**Q4 What does success with --test-passphrase demonstrate, and what does it not demonstrate?**

A successful exit status (0) demonstrates that the supplied passphrase successfully unlocks an active keyslot in the LUKS metadata and can derive the master volume encryption key.
However, it does not create a plaintext mapping in `/dev/mapper/`, does not mount any filesystem, and does not verify the structural integrity or existence of the filesystem (`ext4`) contained within the volume.

**Why must old headers be protected, even after a passphrase change?**

In LUKS, rotating or changing a passphrase simply overwrites or replaces a keyslot holding the encrypted master key; it does not re-encrypt the underlying data volume. A backup of an older header still contains a valid copy of the master key decryptable with the previous passphrase. Anyone who obtains that old backup and knows the former passphrase can restore the header or decrypt the storage blocks directly, completely bypassing the passphrase revocation.

**P3 Evidence to retain Image/loop-device association, open state and reading of the fictitious file, absence of the mapping after closure, exit statuses with the incorrect and then the correct passphrase. For the header, retain only its permissions and fingerprint; never attach it.**

<div align="center">
  <img src="images\im3.png" alt="" width="500">
  <p><em>Figure 3: Wrong passphrase</em></p>
</div>

<div align="center">
  <img src="images\im5.png" alt="" width="500">
  <img src="images\im4.png" alt="" width="500">
  <p><em>Figure 4: Evidence for P3</em></p>
</div>


## 5/Software versions and security advisories

**Q5 Why can comparing only 9.6p1 with the upstream version number produce an incorrect diagnosis?** 

Linux distributions like Ubuntu backport security fixes: maintainers extract a security patch from a newer release and apply it directly to the older, stable package version without bumping the upstream version number (9.6p1). Checking only 9.6p1 would falsely report the system as vulnerable even if the patch is present.

**Distinguish the installed version, the candidate version and the fixed-version threshold specific to Ubuntu 24.04.**

- Installed version: The exact version currently unpacked and running on the local system (queried via dpkg-query).
- Candidate version: The version available in configured APT repositories that APT would install upon running apt upgrade (shown in apt-cache policy).
- Fixed-version threshold: The specific package revision (including Ubuntu release and patch suffix, e.g., 1:9.6p1-3ubuntu13.3) defined in a Canonical security advisory from which the vulnerability is resolved

**Q6 Does your comparison allow you to declare the entire system up to date? State a decision limited to the package and advisory studied, then explain what a repository signature does not guarantee about the software contents.**

No. Comparing a single package (openssh-client) against one advisory only verifies that specific component. Other packages on the system may still have unpatched vulnerabilities.

An APT repository signature (via GPG/Signed-By) guarantees the integrity and provenance of the package index (confirming it was released by Ubuntu and not tampered with in transit). It does not guarantee that the software is bug-free, that no zero-day vulnerabilities exist, or that upstream source code is intrinsically secure.

**P4 Evidence to retain Installed and candidate versions; comparison result for the historical advisory; reference, date and decision for the recent advisory. One small table is sufficient; clearly identify any check that remains incomplete.**

| Item | Details / Value |
| :--- | :--- |
| **Target Package** | `openssh-client` |
| **Installed Version** | `1:9.6p1-3ubuntu13.20` |
| **Candidate Version** | `1:9.6p1-3ubuntu13.20` |
| **Historical Advisory** | **USN-6859-1** (July 1, 2024) |
| **Historical Threshold** | `1:9.6p1-3ubuntu13.3` |
| **Historical Evaluation** | **Threshold reached** (`1:9.6p1-3ubuntu13.20` $\ge$ `1:9.6p1-3ubuntu13.3`) |
| **Recent Advisory** | **USN-8928-1** (October 14, 2026) |
| **Recent Threshold** | `1:9.6p1-3ubuntu13.20` |
| **Recent Evaluation** | **Threshold reached** — System is patched against this advisory |
| **APT Signed-By** | `/usr/share/keyrings/ubuntu-archive-keyring.gpg` |

## 6/Independent task on a protected delivery

**A1. Create two new files and a hash manifest identifying them. Sign this manifest with the existing key. Prepare a copy in which only one result is modified, without recalculating the signed reference.**

Two fictitious result files (`data1.txt` and `data2.txt`) were generated. A hash manifest (`manifeste.sha256`) was computed to reference their respective SHA-256 digests. This manifest was then cryptographically signed using the lab's RSA private key (`signer.key`), producing `manifeste.sig`.

<div align="center">
  <img src="images\im6.png" alt="" width="500">
  <p><em>Figure 6: Evidence for part A1</em></p>
</div>

To simulate an unauthorized alteration, a replica directory was created (`livraison-alteree`) containing identical copies of the files, manifest, and signature. In this replica, `data2.txt` was modified directly without updating the manifest or re-generating the digital signature.

**A2. Store the original delivery, the manifest and its signature in the existing LUKS volume.
Demonstrate that the files recovered after closing and reopening the volume match the approved
manifest. Then close the mapping and verify its absence. Reuse the volume without running truncate,
luksFormat or mkfs.ext4 again.**

The legitimate distribution files (`data1.txt`, `data2.txt`, `manifeste.sha256`, `manifeste.sig`) were transferred into the unlocked LUKS2 volume mounted at `/mnt/tp4-coffre`. 

The filesystem was unmounted, and the dm-crypt device mapping was closed. Upon querying `/dev/mapper/tp4_coffre`, the operating system confirmed the mapping was removed.

To verify persistence and confidentiality at rest, the volume was subsequently re-authenticated, unlocked, and re-mounted. Executing `sha256sum -c manifeste.sha256` against the recovered files confirmed their integrity with zero degradation. Finally, the mount was cleanly detached and the crypt mapping closed again.

<div align="center">
  <img src="images\im7.png" alt="" width="500">
  <p><em>Figure 7: Evidence for part A2</em></p>
</div>

**A3. Another member acts as the verifying partner. Using the separately approved public-key fingerprint, this member must accept the original delivery and reject the modified copy. Explain which check fails, then state one limitation related to the signer and one related to the open volume.**

#### 1. Verification Decisions
* **Legitimate Delivery:** 
  The signature on the manifest is mathematically valid against the approved public key (`Verified OK`). The data integrity check confirms both files match the approved digests (`data1.txt: OK`, `data2.txt: OK`). The partner accepts the delivery.
* **Altered Delivery:** 
  The signature verification on `manifeste.sha256` still succeeds (`Verified OK`) because the manifest text itself was not modified. However, the subsequent data verification rejects the package: `data2.txt: FAILED` with a non-zero exit code (`exit status=1`). The partner rejects the delivery because file integrity fails despite a valid manifest signature.

#### 2. Reasoned Limitations
* **Limitation related to the signer:** 
  A valid cryptographic signature only proves authenticity (origin) and transit integrity; it does not ensure that the signed content is accurate, safe, or free of malicious payload. A compromised or dishonest signer can legitimately sign corrupt or harmful data.
* **Limitation related to the open volume:** 
  LUKS ensures confidentiality strictly at rest (offline). Once the volume is unlocked and mounted, standard Unix discretionary access controls govern file access; any process running under an authorized or privileged account (`root`) can inspect or alter cleartext files regardless of disk encryption.

<div align="center">
  <img src="images\im8.png" alt="" width="500">
  <p><em>Figure 8: Evidence for part A3</em></p>
</div>

## 7. Synthesis and Conclusion

* **Observed Limitation:** 
  The authenticity chain relies entirely on an out-of-band trust anchor (the initial manual exchange of the public-key fingerprint). While functional for a bilateral exchange, this model does not scale to larger distributed systems without a formal Public Key Infrastructure (PKI) or certificate authority. Furthermore, LUKS encryption protects confidentiality exclusively at rest and offers no integrity protection against an authorized or compromised process running while the device is mounted.
* **Justified Improvement:** 
  To address scale and automated revocation, the architecture could transition from raw RSA keys to an X.509 PKI or automated transparency-log-based signing (such as Sigstore/Cosign). Additionally, combining LUKS2 with `dm-integrity` or an authenticated filesystem would provide cryptographic guarantees against offline block manipulation.
* **Testing Scope:** 
  All core operational checks (positive and negative tests for SHA-256 manifests, RSA digital signatures, LUKS volume creation/recovery, and APT security advisory tracking) were fully executed and validated on the target Ubuntu 24.04 environment.

---

END
