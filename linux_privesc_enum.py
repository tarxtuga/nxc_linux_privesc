#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from nxc.helpers.misc import CATEGORY
import re


class NXCModule:
    """
    Linux Privilege Escalation Vector Enumerator for NetExec
    """

    name = "linux_privesc_enum"
    description = "Linux PrivEsc Enumerator (Sudo, SUID, Caps, Cron, Python, Sockets, Kernel CVEs, Containers, NFS, etc.)"
    supported_protocols = ["ssh"]
    category = CATEGORY.PRIVILEGE_ESCALATION
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.deep = False
        self.verbose = False

        # GTFOBins Sudo
        self.gtfobins_sudo = {
            "7z", "aa-exec", "ab", "acr", "agetty", "alpine", "ansible-playbook",
            "ansible-test", "aoss", "apache2", "apache2ctl", "apt", "apt-get",
            "aptitude", "ar", "arch-nspawn", "aria2c", "arj", "arp", "as",
            "ascii-xfr", "ascii85", "ash", "aspell", "asterisk", "at", "atobm",
            "autoconf", "autoheader", "autoreconf", "awk", "aws", "base32",
            "base58", "base64", "basenc", "basez", "bash", "bashbug", "batcat",
            "bbot", "bc", "bconsole", "bee", "borg", "bpftrace", "bridge",
            "bundle", "bundler", "busctl", "busybox", "byebug", "bzip2", "c89",
            "c99", "cabal", "cancel", "capsh", "cargo", "cat", "cc", "cdist",
            "certbot", "chattr", "check_by_ssh", "check_cups", "check_log",
            "check_memory", "check_raid", "check_ssl_cert", "check_statusfile",
            "chmod", "choom", "chown", "chroot", "chrt", "clamscan", "clisp",
            "cmake", "cmp", "cobc", "code", "codex", "column", "comm", "composer",
            "cowsay", "cowthink", "cp", "cpan", "cpio", "cpulimit", "crash",
            "crontab", "csh", "csplit", "csvtool", "ctr", "cupsfilter", "curl",
            "cut", "dash", "date", "dc", "dd", "debugfs", "dhclient", "dialog",
            "diff", "dig", "distcc", "dmesg", "dmsetup", "dnf", "dnsmasq",
            "doas", "docker", "dos2unix", "dosbox", "dotnet", "dpkg", "dstat",
            "dvips", "easy_install", "easyrsa", "eb", "ed", "efax", "egrep",
            "elvish", "emacs", "enscript", "env", "eqn", "espeak", "ex",
            "exiftool", "expand", "expect", "facter", "fail2ban-client",
            "fastfetch", "ffmpeg", "fgrep", "file", "find", "finger", "firejail",
            "fish", "flock", "fmt", "fold", "forge", "fping", "ftp", "fzf",
            "g++", "gawk", "gcc", "gcloud", "gcore", "gdb", "gem", "genie",
            "genisoimage", "getent", "ghc", "ghci", "gimp", "ginsh", "git",
            "gnuplot", "go", "grc", "grep", "gtester", "guile", "gzip",
            "hashcat", "hd", "head", "hexdump", "hg", "highlight", "hping3",
            "iconv", "iftop", "install", "ionice", "ip", "iptables-save", "irb",
            "ispell", "java", "jjs", "joe", "join", "journalctl", "jq",
            "jrunscript", "jshell", "jtag", "julia", "knife", "ksh", "ksshell",
            "ksu", "kubectl", "last", "lastb", "latex", "latexmk", "ld.so",
            "ldconfig", "less", "lftp", "links", "ln", "loginctl", "logrotate",
            "logsave", "look", "lp", "ltrace", "lua", "lualatex", "luatex",
            "lwp-download", "lwp-request", "lxd", "m4", "mail", "make", "man",
            "mawk", "minicom", "more", "mosh-server", "mosquitto", "mount",
            "msfconsole", "msgattrib", "msgcat", "msgconv", "msgfilter",
            "msgmerge", "msguniq", "mtr", "multitime", "mutt", "mv", "mypy",
            "mysql", "nano", "nasm", "nawk", "nc", "ncdu", "ncftp", "needrestart",
            "neofetch", "nft", "nginx", "nice", "nl", "nm", "nmap", "node",
            "nohup", "npm", "nroff", "nsenter", "ntpdate", "nvim", "octave",
            "od", "opencode", "openssl", "openvpn", "openvt", "opkg", "pandoc",
            "passwd", "paste", "pax", "pdb", "pdflatex", "pdftex", "perf",
            "perl", "perlbug", "pexec", "pg", "php", "pic", "pico", "pidstat",
            "pip", "pipx", "pkexec", "pkg", "plymouth", "podman", "poetry",
            "posh", "pr", "procmail", "pry", "psftp", "psql", "ptx", "puppet",
            "pwsh", "pygmentize", "pyright", "python", "qpdf", "rake", "ranger",
            "rc", "readelf", "red", "redcarpet", "redis", "restic", "rev",
            "rlogin", "rlwrap", "rpm", "rpmdb", "rpmquery", "rpmverify",
            "rsync", "rsyslogd", "rtorrent", "ruby", "run-mailcap", "run-parts",
            "runscript", "rustc", "rustdoc", "rustfmt", "rustup", "rvim", "sash",
            "scanmem", "scp", "screen", "script", "scrot", "sed", "service",
            "setarch", "setcap", "setfacl", "setlock", "sftp", "sg", "shred",
            "shuf", "slsh", "smbclient", "snap", "socat", "socket", "soelim",
            "softlimit", "sort", "split", "sqlite3", "sqlmap", "ss", "ssh",
            "ssh-agent", "ssh-copy-id", "ssh-keygen", "ssh-keyscan", "sshfs",
            "sshpass", "sshuttle", "start-stop-daemon", "stdbuf", "strace",
            "strings", "su", "sudo", "sysctl", "systemctl", "systemd-resolve",
            "systemd-run", "tac", "tail", "tailscale", "tar", "task", "taskset",
            "tasksh", "tbl", "tclsh", "tcpdump", "tcsh", "tdbtool", "tee",
            "telnet", "terraform", "tex", "tftp", "tic", "time", "timedatectl",
            "timeout", "tmate", "tmux", "top", "torify", "torsocks", "troff",
            "tsc", "tshark", "ul", "unexpand", "uniq", "unshare", "unsquashfs",
            "unzip", "update-alternatives", "urlget", "uuencode", "uv", "vagrant",
            "valgrind", "varnishncsa", "vi", "view", "vigr", "vim", "vimdiff",
            "vipw", "virsh", "volatility", "w3m", "wall", "watch", "wc",
            "wg-quick", "wget", "whiptail", "whois", "wireshark", "wish",
            "xargs", "xdg-user-dir", "xdotool", "xelatex", "xetex", "xmodmap",
            "xmore", "xpad", "xxd", "xz", "yarn", "yash", "yelp", "yt-dlp",
            "yum", "zathura", "zcat", "zgrep", "zic", "zip", "zless", "zsh",
            "zsoelim", "zypper"
        }

        # GTFOBins SUID
        self.gtfobins_suid = {
            "7z", "aa-exec", "ab", "acr", "agetty", "alpine", "ansible-playbook",
            "ansible-test", "aoss", "apache2", "apache2ctl", "apt", "apt-get",
            "aptitude", "ar", "arch-nspawn", "aria2c", "arj", "arp", "as",
            "ascii-xfr", "ascii85", "ash", "aspell", "asterisk", "at", "atobm",
            "autoconf", "autoheader", "autoreconf", "awk", "aws", "base32",
            "base58", "base64", "basenc", "basez", "bash", "bashbug", "batcat",
            "bbot", "bc", "bconsole", "bee", "borg", "bpftrace", "bridge",
            "bundle", "bundler", "busctl", "busybox", "byebug", "bzip2", "c89",
            "c99", "cabal", "cancel", "capsh", "cargo", "cat", "cc", "cdist",
            "certbot", "chattr", "check_by_ssh", "check_cups", "check_log",
            "check_memory", "check_raid", "check_ssl_cert", "check_statusfile",
            "chmod", "choom", "chown", "chroot", "chrt", "clamscan", "clisp",
            "cmake", "cmp", "cobc", "code", "codex", "column", "comm", "composer",
            "cowsay", "cowthink", "cp", "cpan", "cpio", "cpulimit", "crash",
            "crontab", "csh", "csplit", "csvtool", "ctr", "cupsfilter", "curl",
            "cut", "dash", "date", "dc", "dd", "debugfs", "dhclient", "dialog",
            "diff", "dig", "distcc", "dmesg", "dmsetup", "dnf", "dnsmasq",
            "doas", "docker", "dos2unix", "dosbox", "dotnet", "dpkg", "dstat",
            "dvips", "easy_install", "easyrsa", "eb", "ed", "efax", "egrep",
            "elvish", "emacs", "enscript", "env", "eqn", "espeak", "ex",
            "exiftool", "expand", "expect", "facter", "fail2ban-client",
            "fastfetch", "ffmpeg", "fgrep", "file", "find", "finger", "firejail",
            "fish", "flock", "fmt", "fold", "forge", "fping", "ftp", "fzf",
            "g++", "gawk", "gcc", "gcloud", "gcore", "gdb", "gem", "genie",
            "genisoimage", "getent", "ghc", "ghci", "gimp", "ginsh", "git",
            "gnuplot", "go", "grc", "grep", "gtester", "guile", "gzip",
            "hashcat", "hd", "head", "hexdump", "hg", "highlight", "hping3",
            "iconv", "iftop", "install", "ionice", "ip", "iptables-save", "irb",
            "ispell", "java", "jjs", "joe", "join", "journalctl", "jq",
            "jrunscript", "jshell", "jtag", "julia", "knife", "ksh", "ksshell",
            "ksu", "kubectl", "last", "lastb", "latex", "latexmk", "ld.so",
            "ldconfig", "less", "lftp", "links", "ln", "loginctl", "logrotate",
            "logsave", "look", "lp", "ltrace", "lua", "lualatex", "luatex",
            "lwp-download", "lwp-request", "lxd", "m4", "mail", "make", "man",
            "mawk", "minicom", "more", "mosh-server", "mosquitto", "mount",
            "msfconsole", "msgattrib", "msgcat", "msgconv", "msgfilter",
            "msgmerge", "msguniq", "mtr", "multitime", "mutt", "mv", "mypy",
            "mysql", "nano", "nasm", "nawk", "nc", "ncdu", "ncftp", "needrestart",
            "neofetch", "nft", "nginx", "nice", "nl", "nm", "nmap", "node",
            "nohup", "npm", "nroff", "nsenter", "ntpdate", "nvim", "octave",
            "od", "opencode", "openssl", "openvpn", "openvt", "opkg", "pandoc",
            "passwd", "paste", "pax", "pdb", "pdflatex", "pdftex", "perf",
            "perl", "perlbug", "pexec", "pg", "php", "pic", "pico", "pidstat",
            "pip", "pipx", "pkexec", "pkg", "plymouth", "podman", "poetry",
            "posh", "pr", "procmail", "pry", "psftp", "psql", "ptx", "puppet",
            "pwsh", "pygmentize", "pyright", "python", "qpdf", "rake", "ranger",
            "rc", "readelf", "red", "redcarpet", "redis", "restic", "rev",
            "rlogin", "rlwrap", "rpm", "rpmdb", "rpmquery", "rpmverify",
            "rsync", "rsyslogd", "rtorrent", "ruby", "run-mailcap", "run-parts",
            "runscript", "rustc", "rustdoc", "rustfmt", "rustup", "rvim", "sash",
            "scanmem", "scp", "screen", "script", "scrot", "sed", "service",
            "setarch", "setcap", "setfacl", "setlock", "sftp", "sg", "shred",
            "shuf", "slsh", "smbclient", "snap", "socat", "socket", "soelim",
            "softlimit", "sort", "split", "sqlite3", "sqlmap", "ss", "ssh",
            "ssh-agent", "ssh-copy-id", "ssh-keygen", "ssh-keyscan", "sshfs",
            "sshpass", "sshuttle", "start-stop-daemon", "stdbuf", "strace",
            "strings", "su", "sudo", "sysctl", "systemctl", "systemd-resolve",
            "systemd-run", "tac", "tail", "tailscale", "tar", "task", "taskset",
            "tasksh", "tbl", "tclsh", "tcpdump", "tcsh", "tdbtool", "tee",
            "telnet", "terraform", "tex", "tftp", "tic", "time", "timedatectl",
            "timeout", "tmate", "tmux", "top", "torify", "torsocks", "troff",
            "tsc", "tshark", "ul", "unexpand", "uniq", "unshare", "unsquashfs",
            "unzip", "update-alternatives", "urlget", "uuencode", "uv", "vagrant",
            "valgrind", "varnishncsa", "vi", "view", "vigr", "vim", "vimdiff",
            "vipw", "virsh", "volatility", "w3m", "wall", "watch", "wc",
            "wg-quick", "wget", "whiptail", "whois", "wireshark", "wish",
            "xargs", "xdg-user-dir", "xdotool", "xelatex", "xetex", "xmodmap",
            "xmore", "xpad", "xxd", "xz", "yarn", "yash", "yelp", "yt-dlp",
            "yum", "zathura", "zcat", "zgrep", "zic", "zip", "zless", "zsh",
            "zsoelim", "zypper"
        }

        # Список программ из GTFOBins Capabilities
        self.gtfobins_caps = {
            "gdb", "gzip", "node", "perl", "php", "python", "ruby", "tclsh"
        }

        # Безопасные SUID
        self.safe_suid = {
            "passwd", "sudo", "su", "mount", "umount", "ping", "chfn", "chsh",
            "newgrp", "gpasswd", "fusermount", "pkexec"
        }

    def options(self, context, module_options):
        self.deep = module_options.get("DEEP", "false").lower() == "true"
        self.verbose = module_options.get("VERBOSE", "false").lower() == "true"

    def on_login(self, context, connection):
        self.enum_privesc(context, connection)

    def run_cmd(self, connection, cmd):
        try:
            result = connection.execute(cmd).strip()
            noise_patterns = [
                "Permission denied",
                "Failed to get capabilities",
                "No such file or directory",
                "Operation not supported",
            ]
            lines = result.splitlines()
            filtered = [line for line in lines if not any(p in line for p in noise_patterns)]
            return "\n".join(filtered).strip()
        except Exception:
            return ""

    def extract_section(self, text, start_marker, end_marker=None):
        if not text:
            return ""
        start_idx = text.find(start_marker)
        if start_idx == -1:
            return ""
        start_idx += len(start_marker)
        if end_marker:
            end_idx = text.find(end_marker, start_idx)
            if end_idx == -1:
                return text[start_idx:].strip()
            return text[start_idx:end_idx].strip()
        else:
            return text[start_idx:].strip()

    # ------------------------------------------------------------------
    # Main enumeration logic
    # ------------------------------------------------------------------
    def enum_privesc(self, context, connection):
        context.log.highlight("=== Linux Privilege Escalation Enumeration ===")

        markers = {
            "ID": "__NXC_ID__",
            "SUDO": "__NXC_SUDO__",
            "SUID": "__NXC_SUID__",
            "SGID": "__NXC_SGID__",
            "CAPS": "__NXC_CAPS__",
            "CRON": "__NXC_CRON__",
            "PATH": "__NXC_PATH__",
            "PYTHON": "__NXC_PYTHON__",
            "DOCKER": "__NXC_DOCKER__",
            "CONTAINER": "__NXC_CONTAINER__",
            "K8S": "__NXC_K8S__",
            "NFS": "__NXC_NFS__",
            "LOG": "__NXC_LOG__",
            "TMUX": "__NXC_TMUX__",
            "KERNEL": "__NXC_KERNEL__",
            "GLIBC": "__NXC_GLIBC__",
            "SENS": "__NXC_SENS__",
            "DONE": "__NXC_DONE__"
        }

        big_script = f"""
echo {markers['ID']}
id
echo {markers['SUDO']}
sudo -n -l 2>/dev/null
sudo --version 2>/dev/null | head -n1
echo {markers['SUID']}
find / -perm -4000 -type f 2>/dev/null
echo {markers['SGID']}
find / -perm -2000 -type f 2>/dev/null
echo {markers['CAPS']}
getcap -r / 2>/dev/null
echo {markers['CRON']}
cat /etc/crontab /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/crontabs/* 2>/dev/null
test -w /etc/cron.d && echo "cron_d_writable"
test -w /etc/crontab && echo "crontab_writable"
test -w /var/spool/cron/crontabs && echo "crontabs_writable"
echo {markers['PATH']}
echo $PATH
python3 -c "import os; print('\n'.join([p for p in os.environ.get('PATH','').split(':') if p and os.access(p, os.W_OK)]))" 2>/dev/null
echo {markers['PYTHON']}
python3 -c "import sys,os; print('\n'.join([p for p in sys.path if p and os.access(p, os.W_OK)]))" 2>/dev/null
find /usr/lib /usr/local/lib /opt /etc -name '*.py' -type f -writable 2>/dev/null | head -n 10
echo {markers['DOCKER']}
test -w /var/run/docker.sock && echo "docker_sock_writable"
id | grep -q docker && echo "docker_group"
curl -s http://127.0.0.1:2375/version 2>/dev/null | head -c 200
echo {markers['CONTAINER']}
runc --version 2>/dev/null | head -n1
containerd --version 2>/dev/null | head -n1
docker --version 2>/dev/null | head -n1
echo {markers['K8S']}
curl -sk https://127.0.0.1:10250/pods 2>/dev/null | head -c 200
cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 200
echo {markers['NFS']}
cat /etc/exports 2>/dev/null
showmount -e 127.0.0.1 2>/dev/null
echo {markers['LOG']}
logrotate --version 2>/dev/null | head -n1
grep -E 'create|compress' /etc/logrotate.conf /etc/logrotate.d/* 2>/dev/null | grep -v '#'
echo {markers['TMUX']}
ps aux | grep -i tmux | grep -v grep | grep -- '-S'
find / -type s -name '*tmux*' 2>/dev/null
echo {markers['KERNEL']}
uname -r
test -u /usr/bin/pkexec && echo "pkexec_suid"
pkexec --version 2>/dev/null
echo {markers['GLIBC']}
ldd --version 2>/dev/null | head -n1
echo {markers['SENS']}
test -r /etc/shadow && echo "shadow_readable"
test -w /etc/passwd && echo "passwd_writable"
test -w /etc/sudoers && echo "sudoers_writable"
test -w /etc/ld.so.preload && echo "ld_preload_writable"
find /home /root /tmp /var /opt -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null
find /etc/systemd/system /lib/systemd/system -type f -name '*.service' -writable 2>/dev/null | head -n 10
echo {markers['DONE']}
"""

        raw_output = self.run_cmd(connection, big_script)

        id_section = self.extract_section(raw_output, markers['ID'], markers['SUDO'])
        sudo_section = self.extract_section(raw_output, markers['SUDO'], markers['SUID'])
        suid_section = self.extract_section(raw_output, markers['SUID'], markers['SGID'])
        sgid_section = self.extract_section(raw_output, markers['SGID'], markers['CAPS'])
        caps_section = self.extract_section(raw_output, markers['CAPS'], markers['CRON'])
        cron_section = self.extract_section(raw_output, markers['CRON'], markers['PATH'])
        path_section = self.extract_section(raw_output, markers['PATH'], markers['PYTHON'])
        python_section = self.extract_section(raw_output, markers['PYTHON'], markers['DOCKER'])
        docker_section = self.extract_section(raw_output, markers['DOCKER'], markers['CONTAINER'])
        container_section = self.extract_section(raw_output, markers['CONTAINER'], markers['K8S'])
        k8s_section = self.extract_section(raw_output, markers['K8S'], markers['NFS'])
        nfs_section = self.extract_section(raw_output, markers['NFS'], markers['LOG'])
        log_section = self.extract_section(raw_output, markers['LOG'], markers['TMUX'])
        tmux_section = self.extract_section(raw_output, markers['TMUX'], markers['KERNEL'])
        kernel_section = self.extract_section(raw_output, markers['KERNEL'], markers['GLIBC'])
        glibc_section = self.extract_section(raw_output, markers['GLIBC'], markers['SENS'])
        sens_section = self.extract_section(raw_output, markers['SENS'])

        findings = []
        findings.extend(self.check_groups(id_section))
        findings.extend(self.check_sudo(sudo_section))
        findings.extend(self.check_suid_sgid(suid_section, sgid_section))
        findings.extend(self.check_capabilities(caps_section))
        findings.extend(self.check_cron(cron_section))
        findings.extend(self.check_path_env(path_section))
        findings.extend(self.check_python_lib(python_section))
        findings.extend(self.check_docker(docker_section))
        findings.extend(self.check_container_runtime(container_section))
        findings.extend(self.check_lxd(id_section))
        findings.extend(self.check_kubernetes(k8s_section))
        findings.extend(self.check_nfs(nfs_section))
        findings.extend(self.check_logrotate(log_section))
        findings.extend(self.check_tmux(tmux_section))
        findings.extend(self.check_kernel(kernel_section))
        findings.extend(self.check_glibc(glibc_section))
        findings.extend(self.check_sensitive_files(sens_section))

        if self.deep:
            findings.extend(self.check_deep(context, connection))

        critical_count = 0
        high_count = 0
        medium_count = 0

        for severity, msg in findings:
            if severity == "critical":
                context.log.fail(msg)
                critical_count += 1
            elif severity == "high":
                context.log.highlight(msg)
                high_count += 1
            elif severity == "medium":
                medium_count += 1
                if self.verbose:
                    context.log.success(msg)

        summary = f"=== Summary: {critical_count} critical, {high_count} high"
        if medium_count > 0 and not self.verbose:
            summary += f", {medium_count} medium (use VERBOSE=true to see)"
        else:
            summary += f", {medium_count} medium"
        context.log.highlight(summary + " ===")

    # ------------------------------------------------------------------
    # Check methods
    # ------------------------------------------------------------------
    def check_groups(self, id_text):
        findings = []
        if not id_text:
            return findings
        dangerous_groups = {
            "docker": "Docker group - potential container breakout",
            "lxd": "LXD group - can mount host filesystem",
            "lxc": "LXC group - similar to LXD",
            "disk": "Disk group - raw block device access (debugfs)",
            "adm": "Adm group - can read /var/log (search for passwords)",
            "shadow": "Shadow group - can read /etc/shadow",
        }
        for grp, desc in dangerous_groups.items():
            if f"({grp})" in id_text or f"={grp}" in id_text:
                findings.append(("critical", f"Member of '{grp}' group -> {desc}"))
                if grp == "adm":
                    findings.append(("high", "Adm group -> search passwords in logs: grep -rni 'password' /var/log"))
                elif grp == "disk":
                    findings.append(("high", "Disk group -> use debugfs on /dev/sda1 to read files"))
                elif grp == "docker":
                    findings.append(("high", "Docker group -> run: docker run -v /:/mnt -it alpine chroot /mnt sh"))
                elif grp in ("lxd", "lxc"):
                    findings.append(("high", f"{grp} group -> use lxc to mount host filesystem"))
        return findings

    def check_sudo(self, sudo_text):
        findings = []
        if not sudo_text:
            return findings
        sudo_l = ""
        sudo_ver = ""
        lines = sudo_text.splitlines()
        for line in lines:
            if line.startswith("Sudo version"):
                sudo_ver = line.strip()
            else:
                sudo_l += line + "\n"

        if sudo_l.strip():
            for line in sudo_l.splitlines():
                if "NOPASSWD" in line or "SETENV" in line:
                    findings.append(("critical", f"Sudo: {line.strip()}"))
                elif "env_keep" in line:
                    findings.append(("critical", f"Sudo env_keep: {line.strip()}"))
                elif line.strip().startswith("("):
                    findings.append(("medium", f"Sudo entry: {line.strip()}"))

            if "env_keep+=LD_PRELOAD" in sudo_l:
                findings.append(("critical", "Sudo allows LD_PRELOAD (env_keep) -> Shared library hijacking possible"))
            if "env_keep+=PYTHONPATH" in sudo_l:
                findings.append(("critical", "Sudo allows PYTHONPATH (env_keep) -> Python library hijacking possible"))
            if "SETENV" in sudo_l:
                findings.append(("high", "Sudo allows SETENV -> can set environment variables"))
                if any(prog in sudo_l for prog in ["python", "python3"]):
                    findings.append(("critical", "Sudo allows SETENV with python -> PYTHONPATH hijacking possible"))

            # Проверяем все программы из GTFOBins (контекст sudo)
            for line in sudo_l.splitlines():
                if "NOPASSWD" in line:
                    for prog in self.gtfobins_sudo:
                        if re.search(rf"\b{re.escape(prog)}\b", line):
                            findings.append(("critical", f"Sudo allows '{prog}' with NOPASSWD -> GTFOBins exploit possible"))
                            break

        # Sudo version CVEs
        if sudo_ver:
            version_match = re.search(r"version\s+([\d\.]+)", sudo_ver)
            if version_match:
                version = version_match.group(1)
                try:
                    major, minor, patch = map(int, version.split('.')[:3])
                except:
                    major, minor, patch = 0, 0, 0
                if (major, minor, patch) < (1, 8, 28):
                    findings.append(("critical", f"Sudo version {version} vulnerable to CVE-2019-14287 (RunAs user bypass)"))
                if (major, minor, patch) < (1, 8, 20):
                    findings.append(("critical", f"Sudo version {version} vulnerable to CVE-2017-1000367 (Sudo Squeeze)"))
                if (major, minor, patch) == (1, 8, 31):
                    findings.append(("high", "Sudo version 1.8.31 may be vulnerable to Baron Samedit (CVE-2021-3156)"))
        return findings

    def check_suid_sgid(self, suid_text, sgid_text):
        findings = []
        suids = suid_text.splitlines() if suid_text else []
        sgids = sgid_text.splitlines() if sgid_text else []

        for sbin in suids:
            if not sbin:
                continue
            bname = sbin.split("/")[-1]
            if bname in self.safe_suid:
                continue
            if bname in self.gtfobins_suid:
                findings.append(("critical", f"SUID GTFOBins: {sbin}"))
            elif any(sbin.startswith(d) for d in ["/home", "/tmp", "/opt", "/var/tmp"]):
                findings.append(("high", f"Custom SUID: {sbin}"))
            else:
                if self.verbose:
                    findings.append(("info", f"SUID (not in GTFOBins): {sbin}"))

        for sgid in sgids:
            if not sgid:
                continue
            bname = sgid.split("/")[-1]
            if bname in self.gtfobins_suid:
                findings.append(("medium", f"SGID GTFOBins: {sgid}"))
            elif any(sgid.startswith(d) for d in ["/home", "/tmp", "/opt", "/var/tmp"]):
                findings.append(("high", f"Custom SGID: {sgid}"))

        return findings

    def check_capabilities(self, caps_text):
        findings = []
        if not caps_text:
            return findings
        dangerous_caps = {
            "cap_dac_override": "Can ignore file permissions (read/write any file)",
            "cap_setuid": "Can set UID to 0 (become root)",
            "cap_sys_admin": "Can mount filesystems, manage namespaces (near-root)",
            "cap_sys_ptrace": "Can inject into processes (ptrace)",
        }
        for cap_line in caps_text.splitlines():
            if not cap_line.strip():
                continue
            for cap, desc in dangerous_caps.items():
                if cap in cap_line:
                    bin_path = cap_line.split('=')[0].strip()
                    findings.append(("critical", f"Capability {cap} on {bin_path} -> {desc}"))
                    bname = bin_path.split("/")[-1]
                    if bname in self.gtfobins_caps:
                        findings.append(("high", f"Binary {bname} is in GTFOBins (capabilities context), check for abuse"))
                    if cap == "cap_setuid" and "python" in bname:
                        findings.append(("high", f"Exploit: {bin_path} -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"))
                    elif cap == "cap_dac_override" and "vim" in bname:
                        findings.append(("high", f"Exploit: use {bin_path} to edit /etc/passwd"))
        return findings

    def check_cron(self, cron_text):
        findings = []
        if not cron_text:
            return findings

        if "cron_d_writable" in cron_text:
            findings.append(("critical", "Writable cron directory: /etc/cron.d"))
        if "crontab_writable" in cron_text:
            findings.append(("critical", "Writable file: /etc/crontab"))
        if "crontabs_writable" in cron_text:
            findings.append(("critical", "Writable directory: /var/spool/cron/crontabs"))

        lines = [l for l in cron_text.splitlines() if l.strip() and not l.strip().startswith('#')]
        wildcard_tools = ["tar", "chown", "chmod", "rsync", "cp", "zip"]
        for line in lines:
            parts = line.split()
            if len(parts) >= 2 and "*" in line and any(tool in parts[0] for tool in wildcard_tools):
                findings.append(("high", f"Cron wildcard abuse possible: {line.strip()}"))
        return findings

    def check_path_env(self, path_text):
        findings = []
        if not path_text:
            return findings
        lines = path_text.splitlines()
        if lines:
            for line in lines[1:]:
                if line.strip():
                    findings.append(("high", f"Writable directory in PATH: '{line.strip()}' -> PATH hijacking possible"))
        return findings

    def check_python_lib(self, py_text):
        findings = []
        if not py_text:
            return findings
        lines = py_text.splitlines()
        for line in lines:
            if line.strip():
                if line.startswith("/"):
                    if line.endswith(".py"):
                        findings.append(("critical", f"Writable Python module file: {line.strip()}"))
                    else:
                        findings.append(("high", f"Writable Python sys.path: '{line.strip()}'"))
                else:
                    if self.deep:
                        findings.append(("critical", f"Writable Python module file: {line.strip()}"))
        return findings

    def check_docker(self, docker_text):
        findings = []
        if not docker_text:
            return findings
        if "docker_sock_writable" in docker_text:
            findings.append(("critical", "Writable Docker socket at /var/run/docker.sock"))
        if "docker_group" in docker_text:
            findings.append(("high", "User in docker group -> can run privileged containers"))
        if "ApiVersion" in docker_text:
            findings.append(("critical", "Docker API exposed on port 2375 without TLS"))
        return findings

    def check_container_runtime(self, container_text):
        findings = []
        if not container_text:
            return findings

        runc_ver = ""
        containerd_ver = ""
        for line in container_text.splitlines():
            if "runc version" in line:
                runc_ver = line.strip()
            elif "containerd version" in line:
                containerd_ver = line.strip()

        if runc_ver:
            version = re.search(r"runc version (\d+)\.(\d+)", runc_ver)
            if version:
                major, minor = map(int, version.groups())
                if (major, minor) < (1, 1) or (major == 1 and minor < 12):
                    findings.append(("critical", f"runc version {runc_ver} vulnerable to Leaky Vessels (CVE-2024-21626)"))
                if "1.0-rc" in runc_ver or re.search(r"runc version 0\.", runc_ver):
                    findings.append(("critical", f"runc version {runc_ver} vulnerable to CVE-2019-5736"))

        if containerd_ver:
            version = re.search(r"containerd version (\d+)\.(\d+)\.(\d+)", containerd_ver)
            if version:
                major, minor, patch = map(int, version.groups())
                if (major == 1 and minor < 3) or (major == 1 and minor == 3 and patch < 7) or (major == 1 and minor == 4 and patch < 3):
                    findings.append(("high", f"containerd version {containerd_ver} vulnerable to CVE-2020-15257"))
        return findings

    def check_lxd(self, id_text):
        findings = []
        if not id_text:
            return findings
        if "lxd" in id_text or "lxc" in id_text:
            findings.append(("critical", "User in lxd/lxc group -> can mount host filesystem"))
            findings.append(("high", "Exploit: lxc image import ... ; lxc init ... ; lxc config device add ... ; lxc start ... ; lxc exec ... /bin/sh"))
        return findings

    def check_kubernetes(self, k8s_text):
        findings = []
        if not k8s_text:
            return findings
        if '"items"' in k8s_text:
            findings.append(("critical", "Unauthenticated Kubelet API on port 10250 -> can execute commands in pods"))
        token_lines = [line for line in k8s_text.splitlines() if len(line) > 100 and not line.startswith("curl:")]
        if token_lines:
            findings.append(("high", "Potential service account token found (see output)"))
        return findings

    def check_nfs(self, nfs_text):
        findings = []
        if not nfs_text:
            return findings
        if "no_root_squash" in nfs_text:
            findings.append(("critical", "NFS export with no_root_squash found -> can mount and create SUID root shell"))
        if "Export list" in nfs_text:
            findings.append(("medium", "NFS exports available (showmount)"))
        return findings

    def check_logrotate(self, log_text):
        findings = []
        if not log_text:
            return findings
        lines = log_text.splitlines()
        version = ""
        create = False
        for line in lines:
            if "logrotate" in line and "version" in line.lower():
                version = line.split()[-1]
            if "create" in line or "compress" in line:
                create = True

        if version in ["3.8.6", "3.11.0", "3.15.0", "3.18.0"]:
            findings.append(("high", f"Logrotate version {version} potentially vulnerable to logrotten"))
        if create:
            findings.append(("high", "Logrotate uses 'create' directive (logrotten may work)"))
        return findings

    def check_tmux(self, tmux_text):
        findings = []
        if not tmux_text:
            return findings
        lines = tmux_text.splitlines()
        for line in lines:
            if "tmux" in line and "-S" in line:
                findings.append(("high", f"Tmux session with custom socket: {line.strip()}"))
        for line in lines:
            if line.startswith("/") or "srw" in line:
                if "rw" in line:
                    findings.append(("high", f"Potential tmux socket hijack: {line.strip()}"))
        return findings

    def check_kernel(self, kernel_text):
        findings = []
        if not kernel_text:
            return findings
        kernel = ""
        pkexec_suid = False
        pkexec_ver = ""
        for line in kernel_text.splitlines():
            if not kernel and re.match(r"^\d+\.\d+", line):
                kernel = line.strip()
            if "pkexec_suid" in line:
                pkexec_suid = True
            if "pkexec version" in line.lower():
                pkexec_ver = line.strip()

        if kernel:
            # Dirty Pipe (CVE-2022-0847)
            if re.search(r"^5\.(8|9|10|11|12|13|14|15|16|17)", kernel):
                findings.append(("critical", "Kernel potentially vulnerable to Dirty Pipe (CVE-2022-0847)"))
            # Netfilter OOB Write (CVE-2022-25636)
            if re.search(r"^5\.(4|5|6|13)", kernel):
                findings.append(("critical", "Kernel potentially vulnerable to Netfilter OOB Write (CVE-2022-25636)"))
            # Netfilter Heap OOB Write (CVE-2021-22555)
            if re.search(r"^5\.(1[01]|[2-9])", kernel) or kernel.startswith("4."):
                findings.append(("high", "Kernel possibly vulnerable to Netfilter Heap OOB Write (CVE-2021-22555)"))
            # nf_tables UAF (CVE-2023-32233)
            if re.search(r"^[0-6]\.", kernel) and not kernel.startswith("6.3.1"):
                findings.append(("high", "Kernel possibly vulnerable to nf_tables UAF (CVE-2023-32233)"))
            # Dirty Cow (CVE-2016-5195)
            if re.search(r"^(2\.|3\.|4\.[0-7]\.)", kernel):
                findings.append(("critical", "Kernel potentially vulnerable to Dirty Cow (CVE-2016-5195)"))
            # OverlayFS (CVE-2023-0386)
            if re.search(r"^5\.(1[1-9]|[2-9][0-9])", kernel) or kernel.startswith("6."):
                findings.append(("high", "Kernel potentially vulnerable to OverlayFS (CVE-2023-0386)"))
            # Netfilter nf_tables double-free (CVE-2024-1086)
            if re.search(r"^5\.(1[4-9]|[2-9][0-9])", kernel) or (kernel.startswith("6.") and not kernel.startswith("6.7")):
                findings.append(("critical", "Kernel potentially vulnerable to nf_tables double-free (CVE-2024-1086)"))
            # eBPF pointer arithmetic (CVE-2022-23222)
            if re.search(r"^4\.(1[2-9]|[2-9][0-9])", kernel) or re.search(r"^5\.(1[0-6])", kernel):
                findings.append(("high", "Kernel potentially vulnerable to eBPF pointer arithmetic (CVE-2022-23222)"))
            # Ubuntu OverlayFS (CVE-2021-3493) - approximated
            if re.search(r"^4\.4\.", kernel) or re.search(r"^5\.(4|8|11)", kernel):
                findings.append(("high", "Kernel possibly vulnerable to Ubuntu OverlayFS (CVE-2021-3493)"))
            # Legacy kernel vulnerabilities
            if re.search(r"^4\.(4|5|6|7|8|9|10|11|12|13|14)", kernel):
                findings.append(("high", "Kernel possibly vulnerable to eBPF LPE (CVE-2017-16995)"))
            if re.search(r"^4\.(10|11|12|13)", kernel):
                findings.append(("high", "Kernel possibly vulnerable to waitid LPE (CVE-2017-5123)"))
            if re.search(r"^3\.(13|14|15|16)", kernel):
                findings.append(("high", "Kernel possibly vulnerable to futex (Towelroot) LPE (CVE-2014-3153)"))
            # Additional classic CVEs
            if re.search(r"^5\.[0-1]\.", kernel) or re.search(r"^4\.(4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20)", kernel):
                if not kernel.startswith("5.2"):
                    findings.append(("high", "Kernel possibly vulnerable to PTRACE_TRACEME (CVE-2019-13272)"))
            if re.search(r"^4\.(4|5|6|7|8|9)\.", kernel):
                findings.append(("high", "Kernel possibly vulnerable to DCCP UAF (CVE-2017-6074)"))
            if re.search(r"^4\.(4|5|6|7|8)\.", kernel) and not re.search(r"^4\.8\.(1[1-9]|[2-9][0-9])", kernel):
                findings.append(("high", "Kernel possibly vulnerable to af_packet race (CVE-2016-8655)"))
            if re.search(r"^3\.(8|9|10|11|12|13|14|15|16|17|18|19)", kernel) or re.search(r"^4\.[0-3]\.", kernel):
                findings.append(("high", "Kernel possibly vulnerable to keyring UAF (CVE-2016-0728)"))
            if re.search(r"^3\.(8|9|10|11|12|13|14|15|16|17|18|19)\.", kernel):
                findings.append(("high", "Kernel possibly vulnerable to perf_event (CVE-2013-2094)"))
            if re.search(r"^3\.[0-1]\.", kernel) or re.search(r"^2\.6\.(3[9]|4[0-9])", kernel):
                findings.append(("high", "Kernel possibly vulnerable to mempodipper (CVE-2012-0056)"))
            if re.search(r"^2\.6\.(3[0-9])", kernel):
                findings.append(("high", "Kernel possibly vulnerable to RDS (CVE-2010-3904)"))
            if re.search(r"^2\.6\.(3[1-7])", kernel):
                findings.append(("high", "Kernel possibly vulnerable to Full Nelson (CVE-2010-4258)"))
            if re.search(r"^2\.6\.(3[5-7])", kernel):
                findings.append(("high", "Kernel possibly vulnerable to ACPI (CVE-2010-4347)"))

        if pkexec_suid:
            if "0.105" in pkexec_ver:
                findings.append(("critical", "pkexec SUID and version 0.105 -> PwnKit (CVE-2021-4034) likely"))
            else:
                findings.append(("medium", "pkexec has SUID bit set -> check for PwnKit"))
        return findings

    def check_glibc(self, glibc_text):
        findings = []
        if not glibc_text:
            return findings
        version_match = re.search(r"(\d+\.\d+)(?:\.\d+)?", glibc_text)
        if version_match:
            glibc_ver = version_match.group(1)
            try:
                glibc_major, glibc_minor = map(int, glibc_ver.split('.'))
            except:
                return findings
            if (glibc_major, glibc_minor) < (2, 31):
                findings.append(("high", f"glibc version {glibc_ver} may be vulnerable to Looney Tunables (CVE-2023-4911)"))
            if (glibc_major, glibc_minor) < (2, 18):
                findings.append(("critical", f"glibc version {glibc_ver} vulnerable to GHOST (CVE-2015-0235)"))
        return findings

    def check_sensitive_files(self, sens_text):
        findings = []
        if not sens_text:
            return findings
        for line in sens_text.splitlines():
            line = line.strip()
            if not line:
                continue
            if "shadow_readable" in line:
                findings.append(("critical", "/etc/shadow is READABLE"))
            elif "passwd_writable" in line:
                findings.append(("critical", "/etc/passwd is WRITABLE"))
            elif "sudoers_writable" in line:
                findings.append(("critical", "/etc/sudoers is WRITABLE"))
            elif "ld_preload_writable" in line:
                findings.append(("critical", "/etc/ld.so.preload is WRITABLE -> can inject library"))
            elif line.startswith("/"):
                if "id_rsa" in line or "id_dsa" in line or "id_ecdsa" in line or "id_ed25519" in line:
                    findings.append(("high", f"Private key found: {line}"))
                elif ".service" in line:
                    findings.append(("high", f"Writable systemd unit: {line}"))
        return findings

    def check_deep(self, context, connection):
        """Deep checks: credentials, hidden files, writable configs"""
        findings = []
        deep_markers = {
            "CREDS": "__NXC_DEEP_CREDS__",
            "HIDDEN": "__NXC_DEEP_HIDDEN__",
            "CONFIG": "__NXC_DEEP_CONFIG__",
            "HISTORY": "__NXC_DEEP_HISTORY__",
            "DONE": "__NXC_DEEP_DONE__"
        }

        deep_script = r"""
echo __NXC_DEEP_CREDS__
grep -rniE "(password|passwd|secret|token)\s*[:=]\s*\S+" /etc /var/www /opt /home 2>/dev/null | grep -vE '^/etc/(apparmor|ssl|services|nsswitch|debconf|sos|overlayroot|security)' | head -n 20
echo __NXC_DEEP_HIDDEN__
find /home /root /tmp /var/www -type f -name '.*' -writable 2>/dev/null | grep -vE '\.bashrc$|\.bash_logout$|\.profile$|\.viminfo$' | head -n 20
echo __NXC_DEEP_CONFIG__
find /var/www /opt /etc -type f \( -name '.env' -o -name '*.conf' -o -name '*.json' -o -name '*.xml' -o -name '*.php' \) -writable 2>/dev/null | head -n 20
echo __NXC_DEEP_HISTORY__
cat /home/*/.bash_history /home/*/.zsh_history /root/.bash_history /root/.zsh_history 2>/dev/null | grep -iE 'pass|sudo|mysql|ssh|token|secret' | head -n 20
echo __NXC_DEEP_DONE__
"""

        raw = self.run_cmd(connection, deep_script)
        creds_text = self.extract_section(raw, "__NXC_DEEP_CREDS__", "__NXC_DEEP_HIDDEN__")
        hidden_text = self.extract_section(raw, "__NXC_DEEP_HIDDEN__", "__NXC_DEEP_CONFIG__")
        config_text = self.extract_section(raw, "__NXC_DEEP_CONFIG__", "__NXC_DEEP_HISTORY__")
        history_text = self.extract_section(raw, "__NXC_DEEP_HISTORY__", "__NXC_DEEP_DONE__")

        if creds_text:
            findings.append(("high", f"Potential credentials found:\n{creds_text}"))
        if hidden_text:
            findings.append(("high", f"Writable hidden files:\n{hidden_text}"))
        if config_text:
            findings.append(("high", f"Writable config files:\n{config_text}"))
        if history_text:
            findings.append(("medium", f"Sensitive commands in history:\n{history_text}"))

        return findings
