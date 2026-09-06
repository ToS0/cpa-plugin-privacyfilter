package detect

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// PathsConfig configures the path layer, which takes a file system path
// apart at its slashes and reports the identifying segments one by one.
// Ordinary segments, the ones every system has, stay as they are, so the
// model still sees a home directory, a source tree and two files that are
// siblings; what leaves the machine is neither the login name nor the
// customer's name.
type PathsConfig struct {
	// ReplaceUnknown reports every segment outside the preserve list. When
	// false, only segments in Known are reported, which is what the term
	// list finds anyway; the layer then only supplies the segment kinds.
	ReplaceUnknown bool
	// Preserve adds to the built-in list of ordinary segments.
	Preserve []string
	// Known are the literal values of the term list, consulted when
	// ReplaceUnknown is false.
	Known map[string]bool
	// AllFilenames reports a final segment with a file extension as
	// KindFileName like any other unknown segment. When false, the default,
	// the layer leaves file names alone: a file name says what a file is,
	// README.md, main.go, config.yaml, and is the index by which a model
	// finds its way around a tree, while the identifying part of a path
	// sits in the directories. A file named after a customer carries the
	// customer's name, which the term layer finds inside the file name at
	// its word boundary; that layer runs first and needs no help from here.
	// A final segment without an extension is treated as a directory.
	AllFilenames bool
}

// defaultPreserve are the segments that identify nothing: the standard
// directories of a Unix system, the well-known files and directories under
// them that an administrator names every day, and the conventional names of
// source trees. A segment on this list stays as it is, so the model still
// knows that it is looking at the hosts file, an SSH host key, a systemd
// unit or a block device. What identifies a machine or its owner is the
// login name, the customer's name, the project, the host name in a path,
// and those are not on the list. Device nodes such as sda1 or nvme0n1p2
// are recognised by deviceName instead of being listed.
var defaultPreserve = []string{
	// the file system hierarchy
	"home", "root", "usr", "etc", "var", "tmp", "srv", "mnt", "media", "opt",
	"bin", "sbin", "lib", "lib64", "libexec", "share", "local", "include", "src", "dev",
	"proc", "sys", "run", "boot", "log", "cache", "config", "spool", "mail", "lock",
	"backup", "backups", "snap", "flatpak", "lost+found", "srv", "efi", "EFI",
	// /etc and its well-known files and directories
	"hosts", "hostname", "passwd", "group", "shadow", "fstab", "crypttab", "mtab",
	"resolv.conf", "nsswitch.conf", "sudoers", "sudoers.d", "profile", "profile.d",
	"environment", "os-release", "machine-id", "default", "conf.d", "modules-load.d",
	"sysctl.d", "sysctl.conf", "cron.d", "cron.daily", "cron.hourly", "cron.weekly", "crontab",
	"ssh", "sshd_config", "ssh_config", "sshd_config.d", "ssh_config.d", "known_hosts",
	"authorized_keys", "id_rsa", "id_ed25519", "id_ecdsa", "ssh_host_rsa_key", "ssh_host_ed25519_key",
	"ssh_host_ecdsa_key", "ssh_host_rsa_key.pub", "ssh_host_ed25519_key.pub", "ssh_host_ecdsa_key.pub",
	"systemd", "system", "user", "users", "network", "resolved.conf", "journald.conf", "logind.conf",
	"netplan", "NetworkManager", "system-connections", "wireguard", "iptables", "nftables.conf",
	"ufw", "fail2ban", "jail.d", "jail.local", "filter.d", "action.d",
	"nginx", "sites-available", "sites-enabled", "conf-available", "conf-enabled", "nginx.conf",
	"apache2", "httpd", "mods-available", "mods-enabled", "httpd.conf",
	"postfix", "dovecot", "samba", "smb.conf", "nfs", "exports", "cups", "avahi",
	"docker", "daemon.json", "containers", "containerd", "podman", "compose", "docker-compose.yml",
	"docker-compose.yaml", "compose.yml", "compose.yaml", "Dockerfile",
	"apt", "sources.list", "sources.list.d", "dnf", "yum.repos.d", "pacman.d", "zypp",
	"letsencrypt", "live", "archive", "renewal", "ssl", "certs", "private", "pki", "tls",
	"X11", "xorg.conf.d", "udev", "rules.d", "modprobe.d", "grub", "grub2", "grub.d", "grub.cfg",
	"security", "pam.d", "selinux", "apparmor.d", "polkit-1", "dbus-1",
	// /var, /run, /sys, /proc, /dev
	"journal", "lastlog", "wtmp", "btmp", "syslog", "messages", "auth.log", "kern.log",
	"apt", "dpkg", "rpm", "www", "html", "www-data", "mysql", "postgresql", "redis",
	"block", "class", "net", "bus", "devices", "kernel", "module", "firmware", "power_supply",
	"virtual", "dmi", "id", "cpu", "cpuinfo", "meminfo", "mounts", "cmdline", "version",
	"self", "fd", "status", "stat", "environ", "cwd", "exe", "maps",
	"disk", "by-id", "by-uuid", "by-label", "by-path", "by-partuuid", "by-partlabel",
	"mapper", "null", "zero", "random", "urandom", "stdin", "stdout", "stderr", "shm",
	"pts", "input", "snd", "dri", "bus", "usb", "tty", "console", "video", "fuse", "kvm", "loop-control",
	// kernel and boot
	"modules", "vmlinuz", "initrd.img", "initramfs", "config-", "System.map",
	// files without an extension that every repository has
	"Makefile", "makefile", "GNUmakefile", "Justfile", "justfile", "Taskfile", "Rakefile", "Gemfile", "Procfile",
	"Vagrantfile", "Jenkinsfile", "Containerfile", "Podfile", "Brewfile", "Pipfile", "Cargo.lock",
	"README", "LICENSE", "LICENCE", "COPYING", "NOTICE", "AUTHORS", "CONTRIBUTORS", "CONTRIBUTING", "CHANGELOG",
	"CHANGES", "HISTORY", "NEWS", "TODO", "VERSION", "INSTALL", "MANIFEST", "CODEOWNERS",
	// languages, package managers, tools
	"python", "python3", "site-packages", "dist-packages", "__pycache__", "venv", ".venv",
	"node", "npm", ".npm", "go", "pkg", "mod", ".cargo", "cargo", "registry", "rustup", ".rustup",
	"java", "jvm", "ruby", "gems", "perl", "perl5", "php", "composer",
	// source trees and user directories
	"cmd", "internal", "docs", "doc", "test", "tests", "testdata", "examples", "scripts",
	"assets", "static", "public", "templates", "migrations", "api", "app", "apps", "web",
	"Users", "Documents", "Downloads", "Desktop", "Pictures", "Music", "Videos", "Projects",
	".config", ".local", ".cache", ".git", ".github", ".vscode", ".idea", "node_modules", "vendor",
	"target", "build", "dist", "out", "obj", "release", "debug", "state", "data", "db",
	".bashrc", ".zshrc", ".profile", ".bash_profile", ".bash_history", ".zsh_history", ".gitconfig",
	".claude", ".codex", "plugins", "logs", "auths", ".ssh", ".gnupg", "address", "resolve",
	"resolve.conf", "operstate", "carrier", "mtu", "speed", "duplex", "statistics", "uevent",
}

// NewPaths builds the path layer. It reports directory segments as
// KindPathSegment and a final segment with a file extension as
// KindFileName, both with Source "paths".
func NewPaths(cfg PathsConfig) (Detector, error) {
	d := &pathsDetector{cfg: cfg, preserve: make(map[string]bool, len(defaultPreserve)+len(cfg.Preserve))}
	for _, s := range defaultPreserve {
		d.preserve[s] = true
	}
	for _, s := range cfg.Preserve {
		if s = strings.TrimSpace(s); s != "" {
			d.preserve[s] = true
		}
	}
	return d, nil
}

type pathsDetector struct {
	cfg      PathsConfig
	preserve map[string]bool
}

var _ Detector = (*pathsDetector)(nil)

// Name implements Detector.
func (d *pathsDetector) Name() string { return "paths" }

// Scan implements Detector. A path begins at a slash, at "~/", "./" or
// "../" that is not preceded by a letter or digit, so "and/or", "km/h" and
// "TCP/IP" are prose, and the authority of a URL, which begins with two
// slashes, is not a path. It runs over segments of letters, digits and the
// characters ._-~@+% and ends at the first other character.
func (d *pathsDetector) Scan(text string) []Match {
	if text == "" || !strings.Contains(text, "/") {
		return nil
	}
	var out []Match
	for i := 0; i < len(text); {
		start, ok := pathStart(text, i)
		if !ok {
			_, size := utf8.DecodeRuneInString(text[i:])
			i += max(size, 1)
			continue
		}
		end := pathEnd(text, start)
		out = d.segments(text, start, end, out)
		i = end
	}
	return out
}

// pathStart reports whether a path begins at text[i].
func pathStart(text string, i int) (int, bool) {
	if i > 0 {
		prev, _ := utf8.DecodeLastRuneInString(text[:i])
		if isTokenRune(prev) || prev == '/' {
			return 0, false
		}
	}
	rest := text[i:]
	switch {
	case strings.HasPrefix(rest, "//"):
		return 0, false
	case rest[0] == '/':
		return i, true
	case strings.HasPrefix(rest, "~/"), strings.HasPrefix(rest, "./"), strings.HasPrefix(rest, "../"):
		return i, true
	}
	return 0, false
}

// pathEnd returns the offset just past the last segment character of the
// path that begins at start.
func pathEnd(text string, start int) int {
	i := start
	for i < len(text) {
		r, size := utf8.DecodeRuneInString(text[i:])
		if r != '/' && !isSegmentRune(r) {
			break
		}
		i += size
	}
	return i
}

// isSegmentRune reports whether r may be part of a path segment.
func isSegmentRune(r rune) bool {
	switch r {
	case '.', '_', '-', '~', '@', '+', '%':
		return true
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// segments appends one match per reportable segment of text[start:end].
func (d *pathsDetector) segments(text string, start, end int, out []Match) []Match {
	path := text[start:end]
	pos := 0
	for pos < len(path) {
		next := strings.IndexByte(path[pos:], '/')
		segEnd := len(path)
		if next >= 0 {
			segEnd = pos + next
		}
		seg := path[pos:segEnd]
		last := next < 0
		if last {
			// A sentence may end right after the path.
			for len(seg) > 0 && seg[len(seg)-1] == '.' {
				seg = seg[:len(seg)-1]
				segEnd--
			}
		}
		if kind, ok := d.classify(seg, last); ok {
			out = append(out, Match{
				Start:  start + pos,
				End:    start + segEnd,
				Value:  seg,
				Kind:   kind,
				Source: "paths",
			})
		}
		if next < 0 {
			break
		}
		pos = segEnd + 1
	}
	return out
}

// classify decides whether a segment is reported and as what.
func (d *pathsDetector) classify(seg string, last bool) (Kind, bool) {
	switch seg {
	case "", ".", "..", "~":
		return "", false
	}
	if d.preserve[seg] || allDigits(seg) || deviceName(seg) {
		return "", false
	}
	if !d.cfg.ReplaceUnknown && !d.cfg.Known[seg] {
		return "", false
	}
	if last && hasFileExt(seg) {
		if !d.cfg.AllFilenames {
			return "", false
		}
		return KindFileName, true
	}
	return KindPathSegment, true
}

// deviceName reports whether seg is the conventional name of a device node
// or kernel object: a disk, partition, network interface, tty, loop or
// mapper device. Such a name says what a thing is, not whose it is, so it
// stays. A systemd unit name is not covered: units are named after what
// they serve, and that is often a host or a customer.
func deviceName(seg string) bool {
	return rxDevice.MatchString(seg)
}

var rxDevice = regexp.MustCompile(`^(?:` +
	`(?:sd|vd|xvd|hd)[a-z]{1,3}[0-9]*` + `|` + // sda, sdb2, vda1
	`nvme[0-9]+(?:n[0-9]+(?:p[0-9]+)?)?` + `|` + // nvme0, nvme0n1, nvme0n1p2
	`mmcblk[0-9]+(?:p[0-9]+|boot[0-9]+|rpmb)?` + `|` + // mmcblk0p1
	`(?:md|dm|loop|zram|ram|sr|fd|nbd|rbd)[0-9]+` + `|` + // md0, dm-0 below, loop3
	`dm-[0-9]+` + `|` +
	`(?:eth|en[opsx]|wl[opsx]?|ww|br|docker|virbr|veth|tap|tun|vnet|bond|team|vlan|wg|zt|tailscale)[0-9a-f][a-z0-9]*(?:\.[0-9]+)?` + `|` + // eth0, enp3s0, wlan0, eth0.100
	`br-[0-9a-f]+` + `|` + `lo` + `|` +
	`(?:tty|ttyS|ttyUSB|ttyACM|pts|hidraw|video|fb|input|event|mouse|snd|dri|card|renderD)[0-9]*` +
	`)$`)

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// hasFileExt reports whether name ends in an extension the file name
// renderer carries over: a dot that is neither first nor last, followed by
// at most sixteen letters, digits, underscores or hyphens. It mirrors the
// rule of pseudo.fileExt; a segment the renderer would not give an
// extension is still a valid file name pseudonym, only without one.
func hasFileExt(name string) bool {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 || i == len(name)-1 || len(name)-i > 17 {
		return false
	}
	for j := i + 1; j < len(name); j++ {
		c := name[j]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}
