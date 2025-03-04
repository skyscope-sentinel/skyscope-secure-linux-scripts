# Skyscope Secure Linux Scripts

⚡ **Skyscope Sentinel Intelligence - Post Quantum - New & Emerging Threat Mitigation Script for Linux Operating Systems**

---

## Overview

**Skyscope Secure Linux Scripts** is a collection of advanced bash scripts designed to transform any Debian/Ubuntu-based x64 Linux system into a fortified, post-quantum secure environment. Developed under the Skyscope Sentinel Intelligence initiative, this project focuses on mitigating emerging threats, implementing quantum-resistant cryptography, and adapting Linux for modern hardware and future computing paradigms, including quantum computing mechanisms.

The scripts (`fortress_developer.sh`, `fortress_developer_2.sh`, `fortress_developer_3.sh`, `fortress_developer_4.sh`) are tailored for direct application or use within Cubic/chroot environments, ensuring compatibility across all x64 systems and Debian/Ubuntu variants. They provide a balance of usability (GNOME desktop, developer tools) and cutting-edge security, making them ideal for developers, security researchers, and system administrators aiming to future-proof their Linux systems.

---

## Features

### Core Features Across All Scripts
- **Post-Quantum Security:** Compiles Linux 6.14-rc5 with `CONFIG_CRYPTO_KYBER` for lattice-based ciphers, enforces 4096-bit RSA encryption for SSH and disk encryption, and implements quantum-resistant key exchanges (e.g., `sntrup761x25519`).
- **Zero-Trust Architecture:** Implements strict access controls, removes risky binaries, and enforces SELinux, AppArmor, and kernel lockdown mode (`lockdown=confidentiality`).
- **Hardware Compatibility:** Supports all x64 systems with generic drivers (e.g., `e1000e`, `nouveau`, `i915`) and optimizes for specific hardware like Intel i7-12700, Gigabyte B760M-H-DDR4, and ASUS GTX 970.
- **Developer Environment:** Preserves GNOME desktop (`gnome-core`), Python (`python3`, Anaconda3), Go (`golang`), Rust (`cargo`), Msty.ai, and tools like `wget`, `git`, `cmake`, `ffmpeg`, `net-tools`, `docker-compose`, and more.
- **Security Tools:** Auto-configures `ufw`, `rkhunter`, `aide`, `firejail`, `sshguard`, `iptables`, `firewalld`, `fail2ban`, and more with strict policies.
- **Robust Error Handling:** Comprehensive error navigation ensures script completion even with partial failures.
- **Custom Network Naming:** Renames Ethernet interfaces to `net101` for consistency.
- **AI-Enhanced Scheduling:** Integrates AI-generated scheduler optimizations (`SCHED_SMT`, `SCHED_MC`) inspired by [Arighi’s blog](http://arighi.blogspot.com/2024/09/ai-generated-linux-kernel-schedulers-in.html).

### Script-Specific Features

#### `fortress_developer.sh`
- **Focus:** Foundational hardening with a developer-friendly desktop environment.
- **Key Enhancements:** Installs GNOME desktop, Python suites, Anaconda3, Msty.ai, and security tools; compiles a secure 6.14-rc5 kernel with post-quantum ciphers; enforces 4096-bit encryption for SSH and disk encryption.

#### `fortress_developer_2.sh`
- **Focus:** Securing virtualized environments.
- **Key Enhancements:** Hardens virtio drivers, implements fuzz-testing for hypercalls using Syzkaller, and configures quantum-resistant SSH with `sntrup761x25519` key exchange.

#### `fortress_developer_3.sh`
- **Focus:** File system security and integrity.
- **Key Enhancements:** Implements log-structured file system checks for NVMe/SSD drives, uses CRYSTALS-Dilithium for quantum-resistant file signatures, and adds an integrity verification script.

#### `fortress_developer_4.sh`
- **Focus:** Memory-safe system enhancements with Rust.
- **Key Enhancements:** Develops a Rust-based kernel module for memory safety, configures post-quantum TLS for Nginx, and leverages Rust's safety features to reduce system vulnerabilities.

---

## Prerequisites

### Hardware Requirements
- **Architecture:** Any x86_64 system (optimized for Intel i7-12700, Gigabyte B760M-H-DDR4, ASUS GTX 970)
- **Memory:** Minimum 8GB RAM (32GB recommended)
- **Storage:** NVMe/SSD/HDD (script supports NVMe and SATA drives)
- **Network:** Ethernet connection (script renames interfaces to `net101`)

### Software Requirements
- **OS:** Any Debian/Ubuntu-based distribution (e.g., Debian Testing, Ubuntu 20.04+)
- **Environment:** Direct application or Cubic/chroot environment
- **Dependencies:** Internet access for downloading kernel sources, Anaconda3, Msty.ai, and packages

---

## Installation

### Clone the Repository
```bash
git clone https://github.com/skyscope-sentinel/skyscope-secure-linux-scripts.git
cd skyscope-secure-linux-scripts

## Make Scripts Executable ##
chmod +x fortress_developer*.sh

## 1. Running the Scripts ##
## Direct Application on a Live System ##
## Run the scripts in sequence to apply all layers of hardening: ##
sudo bash fortress_developer.sh
sudo bash fortress_developer_2.sh
sudo bash fortress_developer_3.sh
sudo bash fortress_developer_4.sh

## 2. Reboot to apply the new kernel and security settings: ##
sudo reboot
```

## OPTIONAL: Cubic/Chroot Environments ##
## 1. Boot into a Cubic session with your base ISO. ##
## 2. Copy the scripts to the chroot environment: ##
sudo cp fortress_developer*.sh /home/makulu/
sudo chroot /path/to/chroot
cd /home/makulu

## 3. Run the scripts in sequence: ##
./fortress_developer.sh
./fortress_developer_2.sh
./fortress_developer_3.sh
./fortress_developer_4.sh

## 4. Generate the ISO in Cubic and test it in a virtual machine (e.g., VirtualBox, QEMU). ##


Usage
Each script builds on the previous one, adding layers of security and functionality:
fortress_developer.sh
Sets up a secure base system with GNOME desktop, developer tools, and initial post-quantum security measures.

Post-Run Checks:
Verify GNOME desktop: gnome-session

Check kernel: uname -r (should show 6.14-rc5-fortress)

Confirm tools: python3 --version, cargo --version, /opt/anaconda3/bin/conda --version, msty --version

Security services: systemctl status ufw fail2ban selinux

Network naming: ip a | grep net101

SSH key strength: ssh-keygen -l -f /root/.ssh/id_rsa (should show 4096-bit RSA)

fortress_developer_2.sh
Enhances security for virtualized environments.

Post-Run Checks:
Verify virtio security: systemctl status libvirtd

Check Syzkaller logs for hypercall fuzz-testing: journalctl | grep syzkaller

fortress_developer_3.sh
Focuses on file system security and integrity.

Post-Run Checks:
Run integrity verification: /usr/local/bin/verify_integrity.sh

Check file system logs: journalctl | grep fsck

fortress_developer_4.sh
Implements memory-safe enhancements with Rust.

Post-Run Checks:
Verify Rust kernel module: dmesg | grep "Rust kernel module loaded"

Test post-quantum TLS: nginx -t (if Nginx is installed)

Security Details

Post-Quantum Security

Kernel-Level: All scripts compile Linux 6.14-rc5 with CONFIG_CRYPTO_KYBER for lattice-based ciphers, ensuring quantum resistance at the kernel level.

Cryptography: Enforces 4096-bit RSA keys for SSH with sntrup761x25519 key exchange, and uses AES-512 with Argon2id for disk encryption.

File Signatures: fortress_developer_3.sh implements CRYSTALS-Dilithium for quantum-resistant file signatures.

TLS: fortress_developer_4.sh configures post-quantum TLS with sntrup761x25519 for secure network communication.


Threat Mitigation

Zero-Trust: Removes risky binaries, enforces strict access controls, and uses kernel lockdown mode.

Virtualization Security: fortress_developer_2.sh secures virtio drivers and fuzz-tests hypercalls.

File System Integrity: fortress_developer_3.sh ensures log-structured file system checks and integrity verification.

Memory Safety: fortress_developer_4.sh leverages Rust for memory-safe kernel modules, reducing vulnerabilities.


Contributing

We welcome contributions to enhance the security, compatibility, and functionality of Skyscope Secure Linux Scripts. To contribute:
Fork the repository.

Create a new branch: git checkout -b feature/your-feature.

Make your changes and commit: git commit -m "Add your feature".

Push to your branch: git push origin feature/your-feature.

Open a pull request with a detailed description of your changes.

Please ensure your contributions align with the project's focus on post-quantum security, threat mitigation, and broad x64 compatibility.


License
This project is licensed under the MIT License - see the LICENSE file for details.


Acknowledgments

LWN.net GuestIndex: For insights into confidential computing, file system security, and Rust in system programming (LWN GuestIndex).

Arighi’s Blog: For AI-generated scheduler insights (link).

felsocim/LKM: For LKM security concepts (link).

ITProToday: For articles on lockdown mode, eBPF, and zero-trust security.



Developed by: Casey Jay Topojani
GitHub: skyscope-sentinel
Business Name: Skyscope Sentinel Intelligence
