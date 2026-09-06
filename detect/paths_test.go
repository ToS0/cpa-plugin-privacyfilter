package detect_test

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

func newPaths(t *testing.T, cfg detect.PathsConfig) detect.Detector {
	t.Helper()
	d, err := detect.NewPaths(cfg)
	if err != nil || d == nil {
		t.Fatalf("NewPaths: %v", err)
	}
	return d
}

// values renders matches as kind:value for comparison.
func values(ms []detect.Match) string {
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		parts = append(parts, string(m.Kind)+":"+m.Value)
	}
	return strings.Join(parts, " ")
}

func TestPaths_SegmentsOfAbsolutePath(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	text := "Der Code liegt in /home/mwendler/Projekte/kunde-x/src/main.go, die Doku in /home/mwendler/Projekte/kunde-x/README.md."
	got := d.Scan(text)
	assertDisjointSorted(t, text, got)
	want := "path_segment:mwendler path_segment:Projekte path_segment:kunde-x filename:main.go " +
		"path_segment:mwendler path_segment:Projekte path_segment:kunde-x filename:README.md"
	if values(got) != want {
		t.Fatalf("Scan =\n%s\nwant\n%s", values(got), want)
	}
	// The sentence's full stop is not part of the file name.
	if last := got[len(got)-1]; text[last.End:] != "." {
		t.Fatalf("trailing dot swallowed: %q", text[last.Start:])
	}
}

func TestPaths_PreservedAndSkipped(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true, Preserve: []string{"Container"}})
	cases := map[string]string{
		"/mnt/part4/Container/cliproxyapi/config.yaml": "path_segment:part4 path_segment:cliproxyapi filename:config.yaml",
		"/etc/systemd/system/x.service":                "filename:x.service",
		"/proc/1234/status":                            "",
		"~/.config/nvim/init.lua":                      "path_segment:nvim filename:init.lua",
		"../kunde-x/./build/out":                       "path_segment:kunde-x",
		"/usr/local/bin":                               "",
		"/":                                            "",
		"/kunde-x/":                                    "path_segment:kunde-x",
		"cd /srv/nuc && ls":                            "path_segment:nuc",
	}
	for text, want := range cases {
		got := d.Scan(text)
		assertDisjointSorted(t, text, got)
		if values(got) != want {
			t.Errorf("Scan(%q) = %q, want %q", text, values(got), want)
		}
	}
}

// j joins bare segments into an absolute path at run time. The test source
// holds no slash path on purpose: a path in the source would be rewritten
// by the very plugin under test when the file travels through it.
func j(segs ...string) string { return "/" + strings.Join(segs, "/") }

// The ordinary names of a system stay: well-known files under etc, the
// device nodes, the tool directories. What names the owner, the customer
// or the machine is still reported, a unit name included, because a unit
// is often named after what it serves.
func TestPaths_OrdinaryNamesStay(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	untouched := []string{
		j("etc", "hosts"), j("etc", "hostname"), j("etc", "resolv.conf"), j("etc", "ssh", "sshd_config"),
		j("etc", "ssh", "ssh_host_ed25519_key.pub"), j("etc", "NetworkManager", "system-connections"),
		j("etc", "wireguard"), j("etc", "nginx", "sites-enabled"), j("etc", "docker", "daemon.json"),
		j("etc", "apt", "sources.list.d"), j("etc", "letsencrypt", "live"), j("etc", "cron.d"),
		j("var", "log", "journal"), j("var", "log", "syslog"), j("var", "lib", "docker", "containers"),
		j("dev", "sda1"), j("dev", "nvme0n1p2"), j("dev", "dm-0"), j("dev", "mapper"), j("dev", "disk", "by-id"),
		j("dev", "null"), j("dev", "ttyUSB0"), j("sys", "class", "net", "eth0", "address"),
		j("sys", "class", "net", "wlp3s0"), j("proc", "1234", "status"), j("proc", "cpuinfo"),
		j("usr", "lib", "python3", "dist-packages"), j("usr", "lib", "systemd", "system"),
		j("usr", "lib", "modules"), j("boot", "grub", "grub.cfg"), j("boot", "efi", "EFI"),
		j("run", "systemd", "resolve"), "~/" + strings.Join([]string{".ssh", "known_hosts"}, "/"), "~/" + strings.Join([]string{".config", "systemd", "user"}, "/"),
		j("opt", "containerd", "bin"), j("var", "www", "html"),
	}
	for _, path := range untouched {
		if got := d.Scan("see " + path + " now"); len(got) != 0 {
			t.Errorf("Scan(%q) = %q, want nothing", path, values(got))
		}
	}
	reported := map[string]string{
		j("home", "alice", "kunde-x"):                         "path_segment:alice path_segment:kunde-x",
		j("etc", "nginx", "sites-enabled", "kunde-x.conf"):    "filename:kunde-x.conf",
		j("etc", "wireguard", "wg0.conf"):                     "filename:wg0.conf",
		j("var", "log", "nginx", "kunde-x.log"):               "filename:kunde-x.log",
		j("mnt", "nas01", "fotos"):                            "path_segment:nas01 path_segment:fotos",
		j("opt", "myapp", "kunde-x", "config.yaml"):           "path_segment:myapp path_segment:kunde-x filename:config.yaml",
		j("etc", "systemd", "system", "backup-nas01.service"): "filename:backup-nas01.service",
		j("dev", "disk", "by-label", "nas01-data"):            "path_segment:nas01-data",
	}
	for text, want := range reported {
		if got := values(d.Scan(text)); got != want {
			t.Errorf("Scan(%q) = %q, want %q", text, got, want)
		}
	}
}

func TestPaths_ProseAndURLsUntouched(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	for _, text := range []string{
		"and/or, km/h, TCP/IP, 1/2 und 3/4",
		"https://example.com/kunde-x/docs",
		"file:///home/mwendler/x",
		"a//b",
		"Version 1.2/rc1",
		"nichts zu tun",
	} {
		if got := d.Scan(text); len(got) != 0 {
			t.Errorf("Scan(%q) = %q, want nothing", text, values(got))
		}
	}
	// The path after a URL's query is still prose, but a path after a
	// space is a path.
	if got := d.Scan("siehe https://example.com/x und /home/mwendler"); values(got) != "path_segment:mwendler" {
		t.Errorf("mixed = %q", values(got))
	}
}

func TestPaths_KnownOnly(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: false, Known: map[string]bool{"kunde-x": true}})
	got := d.Scan("/home/mwendler/Projekte/kunde-x/src/main.go")
	if values(got) != "path_segment:kunde-x" {
		t.Fatalf("Scan = %q, want only the known segment", values(got))
	}
}

func TestPaths_UnicodeSegments(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	text := "in /home/mwendler/Bücher/Übersicht.txt steht es"
	got := d.Scan(text)
	assertDisjointSorted(t, text, got)
	if values(got) != "path_segment:mwendler path_segment:Bücher filename:Übersicht.txt" {
		t.Fatalf("Scan = %q", values(got))
	}
}
