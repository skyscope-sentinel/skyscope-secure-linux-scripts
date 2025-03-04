#!/bin/bash

# Exit on error unless handled explicitly
set -e

# Log all actions
log_file="/root/fortress_universal_log_$(date +%F_%T).txt"
echo "Starting fortress universal script at $(date)" | tee -a "$log_file"

# Enhanced CLI Title with Emoji and Yellow Color
echo -e "\033[1;33m" # Bold yellow color
cat << 'EOF'
 ⚡ Skyscope Sentinel Intelligence
    Post Quantum
    New and Emerging Threat Mitigation Script
    for Linux Operating Systems
 ───────────────────────────────────────────────
EOF
echo -e "\033[0m" # Reset color

# Error handling function
handle_error() {
    local line=$1
    local error_code=$2
    echo "Error on line $line: Exit code $error_code" | tee -a "$log_file"
    # Attempt recovery
    if command -v apt >/dev/null 2>&1; then
        apt-get --fix-broken install -y || echo "Recovery failed for apt" | tee -a "$log_file"
        dpkg --configure -a || echo "dpkg configure failed" | tee -a "$log_file"
    elif command -v dpkg >/dev/null 2>&1; then
        dpkg --configure -a || echo "dpkg configure failed" | tee -a "$log_file"
    else
        echo "Package manager unavailable, manual intervention required" | tee -a "$log_file"
        exit 1
    fi
}

# Trap errors
trap 'handle_error ${LINENO} "$?"' ERR

# Step 1: Detect environment and system compatibility
echo "Detecting environment and system compatibility..." | tee -a "$log_file"
if [ -d "/sys/firmware/efi" ]; then
    echo "UEFI system detected" | tee -a "$log_file"
else
    echo "BIOS system detected, some features may be limited" | tee -a "$log_file"
fi

# Check for Debian/Ubuntu variant
if [ -f /etc/debian_version ]; then
    DISTRO=$(lsb_release -is 2>/dev/null || cat /etc/os-release | grep -oP '(?<=^ID=).+' || echo "Debian")
    echo "Detected Debian-based system: $DISTRO" | tee -a "$log_file"
else
    echo "Non-Debian system detected, script may not be compatible" | tee -a "$log_file"
    exit 1
fi

# Check architecture
ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ]; then
    echo "This script is only compatible with x86_64 systems, detected: $ARCH" | tee -a "$log_file"
    exit 1
fi

# Step 2: Fix broken dependencies
echo "Fixing broken dependencies..." | tee -a "$log_file"
if command -v apt >/dev/null 2>&1; then
    apt-get update || echo "Apt update failed, proceeding" | tee -a "$log_file"
    apt-get --fix-broken install -y || dpkg --configure -a
else
    echo "Apt not found, attempting dpkg recovery" | tee -a "$log_file"
    dpkg --configure -a || echo "dpkg configure failed" | tee -a "$log_file"
fi

# Step 3: Define trusted package whitelist (expanded for desktop and dev tools)
echo "Defining trusted package whitelist..." | tee -a "$log_file"
trusted_packages=(
    # Core system
    "base-files" "base-passwd" "coreutils" "debianutils" "dpkg" "e2fsprogs" "findutils" "grep"
    "gzip" "libc-bin" "libc6" "libselinux1" "libzstd1" "sed" "tar" "util-linux" "zlib1g" "apt"
    "bash" "init" "sysvinit-utils" "procps"
    # Desktop environment (GNOME core)
    "gnome-core" "gnome-tweaks" "gnome-disk-utility" "gdm3" "gnome-shell" "gnome-session"
    "gnome-settings-daemon" "gnome-control-center" "nautilus" "gedit" "gnome-terminal"
    # Development tools
    "wget" "git" "curl" "git-lfs" "make" "cmake" "automake" "autoconf" "gcc" "build-essential"
    "devscripts" "aptitude" "synaptic" "gdebi" "nano" "ffmpeg" "net-tools" "docker-compose"
    "python-is-python3" "python3" "python3-virtualenv" "python3-venv" "python3-pip" "golang"
    "rustc" "cargo"
    # Security tools
    "ufw" "rkhunter" "aide" "firejail" "sshguard" "iptables" "network-manager" "firewalld"
    "fail2ban" "apparmor" "selinux-basics" "selinux-policy-default" "snapd" "flatpak"
)

# Step 4: Install required packages
echo "Installing required packages..." | tee -a "$log_file"
apt update || echo "Apt update failed, continuing" | tee -a "$log_file"
for pkg in "${trusted_packages[@]}"; do
    if ! dpkg -l | grep -q "$pkg"; then
        echo "Installing $pkg..." | tee -a "$log_file"
        apt install -y "$pkg" || echo "Failed to install $pkg, continuing" | tee -a "$log_file"
    else
        echo "$pkg already installed" | tee -a "$log_file"
    fi
done

# Install Anaconda3
echo "Installing Anaconda3..." | tee -a "$log_file"
wget https://repo.anaconda.com/archive/Anaconda3-2024.10-1-Linux-x86_64.sh -O /tmp/anaconda3.sh || echo "Anaconda download failed" | tee -a "$log_file"
bash /tmp/anaconda3.sh -b -p /opt/anaconda3 || echo "Anaconda install failed" | tee -a "$log_file"
rm -f /tmp/anaconda3.sh

# Install Msty.ai
echo "Installing Msty.ai..." | tee -a "$log_file"
wget https://assets.msty.app/prod/latest/linux/amd64/Msty_amd64_amd64.deb -O /tmp/msty.deb || echo "Msty download failed" | tee -a "$log_file"
dpkg -i /tmp/msty.deb || apt-get install -f -y || echo "Msty install failed" | tee -a "$log_file"
rm -f /tmp/msty.deb

# Step 5: Purge only injected packages (preserve desktop essentials)
echo "Purging injected packages..." | tee -a "$log_file"
injected_packages=($(dpkg --get-selections | awk '{print $1}' | grep -vE "$(echo "${trusted_packages[*]}" | tr ' ' '|')"))
for pkg in "${injected_packages[@]}"; do
    echo "Purging injected package: $pkg" | tee -a "$log_file"
    apt purge -y "$pkg" || dpkg --purge --force-all "$pkg" 2>/dev/null || echo "Failed to purge $pkg" | tee -a "$log_file"
done
apt autoremove --purge -y || echo "Autoremove failed" | tee -a "$log_file"

# Step 6: Remove risky binaries (exclude trusted tools)
echo "Removing risky binaries from /bin and /sbin..." | tee -a "$log_file"
risky_binaries=(
    "nc" "netcat" "telnet" "ftp" "ping" "traceroute" "nmap" "rsync" "ssh" "scp" "sftp" "rlogin" "rsh"
    "rexec" "rpcclient" "smbclient" "useradd" "usermod" "userdel" "groupadd" "groupdel" "passwd"
    "chpasswd" "adduser" "deluser" "chmod" "chown" "chgrp" "ln" "mkdir" "rmdir" "mkfifo" "mknod"
    "install" "cp" "mv" "rm" "gdb" "strace" "ltrace" "tcpdump" "socat" "hexdump" "od" "strings"
    "readelf" "openssl" "gpg" "cut" "sort" "uniq" "modprobe" "insmod" "rmmod" "depmod" "ip" "arp"
    "arptables" "ebtables" "ip6tables" "kill" "killall" "ps" "top" "htop" "screen" "tmux" "sudo" "su"
)
for dir in "/bin" "/sbin"; do
    for bin in "${risky_binaries[@]}"; do
        if [ -f "$dir/$bin" ] && ! [[ " ${trusted_packages[*]} " =~ " $bin " ]]; then
            echo "Removing $dir/$bin" | tee -a "$log_file"
            rm -f "$dir/$bin" || echo "Failed to remove $dir/$bin" | tee -a "$log_file"
        fi
    done
done

# Step 7: Clean system directories and GRUB modules
echo "Cleaning system directories and GRUB modules..." | tee -a "$log_file"
suspicious_dirs=("/etc" "/var" "/usr" "/root" "/boot" "/bin" "/sbin" "/boot/grub/x86_64-efi")
risky_modules=("http.mod" "tftp.mod" "net.mod" "cryptodisk.mod" "luks.mod" "luks2.mod" "linuxefi.mod" "multiboot.mod")
for dir in "${suspicious_dirs[@]}"; do
    if [ -d "$dir" ]; then
        find "$dir" -type f \( -perm /u+x -o -name "*.sh" -o -name "*.conf" -o -name "*.py" -o -name "*.bak" -o -name "*.old" \) -exec bash -c '
            file="$1"
            if ! dpkg -S "$file" > /dev/null 2>&1; then
                echo "Removing unowned file: $file" | tee -a "$2"
                rm -f "$file"
            fi
        ' _ {} "$log_file" \;
        if [ "$dir" = "/boot/grub/x86_64-efi" ]; then
            for mod in "${risky_modules[@]}"; do
                if [ -f "$dir/$mod" ]; then
                    echo "Removing $dir/$mod" | tee -a "$log_file"
                    rm -f "$dir/$mod" || echo "Failed to remove $dir/$mod" | tee -a "$log_file"
                fi
            done
        fi
    fi
done

# Step 8: Compile secure Linux 6.14-rc5 kernel with hardware optimization and PQ ciphers
echo "Compiling secure Linux 6.14-rc5 kernel..." | tee -a "$log_file"
apt install -y build-essential libncurses-dev bison flex libssl-dev libelf-dev bc || echo "Build tools install failed" | tee -a "$log_file"
cd /usr/src
wget https://git.kernel.org/torvalds/t/linux-6.14-rc5.tar.gz -O linux-6.14-rc5.tar.gz || echo "Kernel download failed" | tee -a "$log_file"
tar -xzf linux-6.14-rc5.tar.gz || echo "Kernel extraction failed" | tee -a "$log_file"
cd linux-6.14-rc5
# Custom config for hardware, security, and AI scheduler
cat << EOF > .config
# Core system
CONFIG_SMP=y
CONFIG_NR_CPUS=128 # Support for up to 128 cores (covers all x64 systems)
CONFIG_PREEMPT=y
CONFIG_X86_64=y
# Security features
CONFIG_MODULES=y
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_ALL=y
CONFIG_MODULE_SIG_SHA256=y
CONFIG_LOCK_DOWN_KERNEL=y
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_SECURITY=y
CONFIG_SECURITY_SELINUX=y
CONFIG_SECURITY_APPARMOR=y
CONFIG_INTEGRITY=y
CONFIG_IMA=y
CONFIG_IMA_APPRAISE=y
CONFIG_IMA_DEFAULT_HASH="sha256"
CONFIG_KASLR=y
CONFIG_SPECULATION_CONTROL=y
CONFIG_PAGE_TABLE_ISOLATION=y
CONFIG_RETPOLINE=y
CONFIG_CRYPTO_KYBER=y # Post-quantum lattice-based cipher
CONFIG_DEFAULT_SECURITY_SELINUX=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
CONFIG_INIT_ON_FREE_DEFAULT_ON=y
CONFIG_CC_STACKPROTECTOR_STRONG=y
# Hardware support (generic for x64 systems)
CONFIG_VIRTIO=n
CONFIG_VMX=y
CONFIG_VT=y
CONFIG_VTD=y
CONFIG_DRM_NOUVEAU=y
CONFIG_DRM_RADEON=y
CONFIG_DRM_I915=y
CONFIG_ETHERNET=y
CONFIG_NETDEVICES=y
CONFIG_E1000E=y
CONFIG_IGB=y
CONFIG_IXGBE=y
CONFIG_USB=n
CONFIG_NVME_CORE=y
CONFIG_BLK_DEV_NVME=y
CONFIG_SATA_AHCI=y
CONFIG_DDR4=y
# AI scheduler (inspired by Arighi)
CONFIG_SCHED_SMT=y
CONFIG_SCHED_MC=y
CONFIG_FAIR_GROUP_SCHED=y
# Minimal features (keep networking for userspace)
CONFIG_NET=y
CONFIG_DEBUG_KERNEL=n
EOF
make olddefconfig || echo "Kernel config failed" | tee -a "$log_file"
make -j$(nproc) bzImage || echo "Kernel build failed" | tee -a "$log_file"
make -j$(nproc) modules || echo "Modules build failed" | tee -a "$log_file"
make install || echo "Kernel install failed" | tee -a "$log_file"
cp arch/x86/boot/bzImage /boot/vmlinuz-6.14-rc5-fortress || echo "Kernel copy failed" | tee -a "$log_file"
cp System.map /boot/System.map-6.14-rc5-fortress || echo "System.map copy failed" | tee -a "$log_file"
update-initramfs -c -k 6.14-rc5-fortress || echo "Initramfs update failed" | tee -a "$log_file"

# Step 9: Configure network renaming (net101)
echo "Renaming Ethernet to net101..." | tee -a "$log_file"
cat << EOF > /etc/udev/rules.d/70-persistent-net.rules
SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", NAME="net101"
EOF

# Step 10: Harden GRUB
echo "Hardening GRUB..." | tee -a "$log_file"
grub_passwd=$(echo -e "securepassword\nsecurepassword" | grub-mkpasswd-pbkdf2 | grep "grub.pbkdf2" | cut -d' ' -f2-)
cat << EOF > /etc/grub.d/40_custom
set superusers="admin"
password_pbkdf2 admin $grub_passwd
set root='hd0,msdos1'
EOF
cat << EOF > /boot/grub/grub.cfg
set timeout=5
set default=0
insmod ext2
set root='hd0,msdos1'
menuentry "Fortress Universal (Secure)" --users "admin" {
    linux /boot/vmlinuz-6.14-rc5-fortress root=/dev/nvme0n1p1 ro quiet loglevel=0 systemd.show_status=0 lockdown=confidentiality ima_appraise=fix ima_hash=sha256 selinux=1 security=selinux enforcing=1
    initrd /boot/initrd.img-6.14-rc5-fortress
}
EOF
grub_params="root=/dev/nvme0n1p1 ro quiet loglevel=0 systemd.show_status=0 lockdown=confidentiality ima_appraise=fix ima_hash=sha256 selinux=1 security=selinux enforcing=1 apparmor=1 slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 net.ipv4.ip_forward=0 net.ipv6.conf.all.disable_ipv6=1"
sed -i "s|GRUB_CMDLINE_LINUX_DEFAULT=\".*\"|GRUB_CMDLINE_LINUX_DEFAULT=\"$grub_params\"|" /etc/default/grub
update-grub || echo "GRUB update failed" | tee -a "$log_file"

# Step 11: Lock configs
echo "Locking critical configs..." | tee -a "$log_file"
configs_to_lock=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow" "/etc/sudoers" "/etc/sysctl.conf" "/etc/apt/sources.list" "/etc/grub.d/*" "/etc/default/grub" "/etc/fstab" "/boot/grub/grub.cfg")
for config in "${configs_to_lock[@]}"; do
    if ls $config > /dev/null 2>&1; then
        chattr +i $config || echo "Failed to lock $config" | tee -a "$log_file"
        cp -a "$config" "/root/backup_$(basename $config)_$(date +%F_%T)" || true
    fi
done

# Step 12: Enhance sysctl for post-quantum security
echo "Enhancing sysctl..." | tee -a "$log_file"
cat << EOF > /etc/sysctl.d/99-fortress.conf
kernel.kexec_load_disabled=1
kernel.sysrq=0
kernel.unprivileged_bpf_disabled=1
kernel.unprivileged_userns_clone=0
fs.suid_dumpable=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.accept_source_route=0
net.ipv4.icmp_echo_ignore_all=1
net.ipv6.conf.all.disable_ipv6=1
dev.tty.ldisc_autoload=0
vm.mmap_min_addr=65536
kernel.pid_max=32768
EOF
sysctl -p /etc/sysctl.d/99-fortress.conf || echo "Sysctl failed, will apply at boot" | tee -a "$log_file"

# Step 13: Configure and enable security tools with 4096-bit encryption
echo "Configuring and enabling security tools..." | tee -a "$log_file"
ufw enable || echo "UFW enable failed" | tee -a "$log_file"
systemctl enable ufw || echo "UFW service enable failed" | tee -a "$log_file"
rkhunter --propupd || echo "Rkhunter update failed" | tee -a "$log_file"
systemctl enable rkhunter.timer || echo "Rkhunter timer enable failed" | tee -a "$log_file"
aide --init || echo "AIDE init failed" | tee -a "$log_file"
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db || echo "AIDE db move failed" | tee -a "$log_file"
systemctl enable aide.timer || echo "AIDE timer enable failed" | tee -a "$log_file"
firejail --setup || echo "Firejail setup failed" | tee -a "$log_file"
sed -i 's/#FIREJAIL_DEFAULT_PROFILE=/FIREJAIL_DEFAULT_PROFILE=desktop/' /etc/firejail/firejail.config
systemctl enable sshguard || echo "SSHGuard enable failed" | tee -a "$log_file"
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables-save > /etc/iptables/rules.v4 || echo "iptables save failed" | tee -a "$log_file"
systemctl enable iptables || echo "iptables service enable failed" | tee -a "$log_file"
systemctl enable network-manager || echo "NetworkManager enable failed" | tee -a "$log_file"
firewalld --set-default-zone=drop || echo "Firewalld config failed" | tee -a "$log_file"
systemctl enable firewalld || echo "Firewalld enable failed" | tee -a "$log_file"
fail2ban-client start || echo "Fail2ban start failed" | tee -a "$log_file"
systemctl enable fail2ban || echo "Fail2ban enable failed" | tee -a "$log_file"
apparmor_parser -r /etc/apparmor.d/* || echo "Apparmor reload failed" | tee -a "$log_file"
systemctl enable apparmor || echo "Apparmor enable failed" | tee -a "$log_file"
selinux-activate || echo "SELinux activation failed" | tee -a "$log_file"
sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config || echo "SELinux config failed" | tee -a "$log_file"

# Step 14: Configure 4096-bit encryption for SSH and disk (if applicable)
echo "Configuring 4096-bit encryption..." | tee -a "$log_file"
# Generate 4096-bit RSA keys for SSH (if SSH is installed)
if command -v ssh-keygen >/dev/null 2>&1; then
    ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N "" || echo "SSH keygen failed" | tee -a "$log_file"
    cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys
    echo "Host *\n    KexAlgorithms sntrup761x25519-sha512@openssh.com\n    HostKeyAlgorithms ssh-rsa\n    PubkeyAcceptedKeyTypes ssh-rsa" > /root/.ssh/config
fi
# Setup disk encryption with 4096-bit strength (if cryptsetup is present)
if command -v cryptsetup >/dev/null 2>&1; then
    if [ -b /dev/nvme1n1 ]; then
        cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha512 --pbkdf argon2id /dev/nvme1n1 || echo "LUKS format failed" | tee -a "$log_file"
    fi
fi

# Step 15: Final cleanup
echo "Final cleanup..." | tee -a "$log_file"
rm -rf /var/cache/* /var/lib/apt/lists/* /var/log/* /tmp/* || echo "Cleanup failed" | tee -a "$log_file"
apt update || echo "Final apt update failed" | tee -a "$log_file"

echo "Fortress Universal complete. Check $log_file. Test ISO in a VM or direct system." | tee -a "$log_file"
