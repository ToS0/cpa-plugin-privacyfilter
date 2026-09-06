# CPA Plugin Privacy Filter

English | [简体中文](README.zh-CN.md)

A privacy filter plugin for [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI). It sits between your
coding assistant and the model provider and replaces identifiers such as host names, IP addresses, e-mail
addresses, the names of people and customers, paths, serial numbers and account numbers with transparent stand-ins
before a request leaves your machine, then puts the real values back into the answer. The model works with the
stand-ins as if they were the real thing, administers a system, edits a config, writes a tool call, without ever
knowing the actual names and IDs.

There are two modes. `redact` is the default and the original plugin: detected secrets, contact data and ID numbers
become `[REDACTED]`, one way. `pseudonymize` is the reason for this fork: your own values from a list, plus
everything the detectors find, become stable pseudonyms of the same shape, and the answer is translated back,
streamed or not. The modes do not compete in detection. Pseudonymize runs the original plugin's automatic
detection as its last layer, after your list and the structural patterns, so everything `redact` would find is
found here too. The difference is what happens to a hit: thrown away, or replaced by something the model can use
and the client gets back as the original. This document is written for `pseudonymize`; `redact` is described under
[Redact mode](#redact-mode).

## Why

Everything a coding assistant sends to a model ends up on somebody else's server: the prompt, the files it reads,
the output of every command it runs. For a consultant, an administrator or a small company that is the whole
working day in clear text: customer names, the people behind them, their e-mail addresses, host names and
addresses of their networks, the paths under which their projects live, machine serials, disk and partition
identifiers, SSH fingerprints, account numbers. A single breach of the provider, a subpoena, a training-data
mistake or a screenshot of a dashboard then exposes not one secret but the map of who works with whom on what,
and with which machines. That map is worth more to an attacker than any one password.

Redacting such values is not enough, because a model that reads `[REDACTED]` cannot reason about the host, the
path or the network any more, and the tool call it writes back is unusable. Pseudonymize mode keeps the request
usable while the provider holds as little as possible: every confidential value is replaced by a stable pseudonym
of the same shape before the request leaves the machine, and the original is put back into the answer before the
client sees it. The model works with `h-e2ba…` and `100.71.4.18` exactly as it would with the real names, the
provider only ever stores the pseudonyms, and the mapping never leaves the local process.

What gets replaced comes from three sources. The **term list** is a plain text file with your own values: customer
names, hosts, domains, people, networks, account numbers. The **structural patterns** need no list and catch what
has a recognisable shape on its own: IP addresses, MACs, e-mail addresses, UUIDs, SSH fingerprints, labelled serial
numbers, IBANs. The **original plugin's detection** runs last, with its Gitleaks rules for API keys, tokens and
connection strings and its recognisers for phone numbers, ID numbers and bank cards, and catches what neither of
the first two lists. The script `machine-ids.py` that ships next to the plugin fills the term list with the identifiers
of a machine, so a new host is covered in a minute.

## Installation

You need a running CLIProxyAPI, the two files from a release or from `dist/` after a build (see
[Building from source](#building-from-source)), and Python 3 for the helper script.

1. Put the shared library and the script into the plugin directory of CLIProxyAPI. This is the directory named by
   `plugins.dir` in `config.yaml`, usually `plugins/`:

   ```text
   plugins/
   ├── privacyfilter.so        # the plugin
   ├── machine-ids.py          # fills the term list, see below
   ├── pseudonym.secret        # you create this once, step 2
   └── terms.txt               # your term list, step 3
   ```

2. Create the secret. The pseudonyms are derived from it; without it the plugin refuses to start. Any random bytes,
   at least 32 of them:

   ```bash
   head -c 48 /dev/urandom | base64 > plugins/pseudonym.secret
   chmod 600 plugins/pseudonym.secret
   ```

3. Create the term list. The quickest way is the script, which asks what to do and writes the file; run it on the
   machine the proxy runs on, with `sudo` so it can read the hardware serials:

   ```bash
   sudo python3 plugins/machine-ids.py
   ```

   Or start with an empty file and fill it by hand, see [The term list](#the-term-list).

4. Enable the plugin in `config.yaml`. This is all a normal installation needs:

   ```yaml
   plugins:
     enabled: true
     dir: "plugins"
     configs:
       privacyfilter:
         enabled: true
         mode: pseudonymize
         terms_file: terms.txt      # relative to the plugin directory
   ```

5. Restart the proxy and look for the plugin in its log:

   ```text
   pluginhost: plugin loaded plugin_id=privacyfilter version=... path=plugins/privacyfilter.so
   ```

   From now on every request logs one line with what it replaced, by kind and count, never the values:

   ```text
   privacyfilter: request pseudonymized ... replacements="host=33 ipv4=1 email=12 path_segment=247 ..."
   ```

The plugin reads the secret and the term list at start only. After every change to `terms.txt` restart the proxy.

## The term list

The term list is the file named by `terms_file`, `plugins/terms.txt` in the layout above. It is the one file you
maintain. Every line is one value that must never leave the machine in clear text, together with the kind of thing
it is, so the plugin can render a pseudonym of the same shape.

### Format

```text
# Anything after a hash is a comment. Blank lines are skipped.

nuc                                  # a literal; without a kind it is a host name
nuc host                             # the same, with the kind spelled out
example-gmbh.de domain               # a domain
markus person ignore_case            # a person; ignore_case also catches "Markus" and "MARKUS"
192.168.10.0/24 cidr                 # a network; addresses inside it keep their structure
DE89370400440532013000 iban          # an account number
kunde-x path_segment                 # a directory name that must not appear in paths
{regex: "(?i)\\bnuc(?:\\.[a-z0-9-]+)*\\b", kind: host}   # a regular expression, YAML form
{value: "Müller & Söhne", kind: person}                   # a literal with spaces, YAML form
```

A plain line is split on white space: the first word is the value, the optional second word the kind, and the
word `ignore_case` sets the flag. A value that contains spaces or starts with `{` or `#` goes into the YAML form,
which takes the same keys as a `terms` entry in `config.yaml`: `value` or `regex`, `kind`, `ignore_case`.

A literal matches at word boundaries only: `nuc` matches in `nuc`, `nuc.local`, `nuc_old` and `NUC-2`, but not in
`nucleus`. Letters and digits continue a word, everything else, including the underscore, ends it. A regular
expression matches wherever it matches, so write the boundaries yourself with `\b` and do not use `^` or `$`: the
expression runs against whole messages, not against single lines.

### Kinds

The kind decides what the pseudonym looks like. The model sees something that has the same shape as the original,
so it keeps working normally, and the plugin can tell a pseudonym from a real value when the answer comes back.

| Kind           | Use it for                                    | Pseudonym                                   |
|----------------|-----------------------------------------------|---------------------------------------------|
| `host`         | host names, with or without domain            | `h-<12 hex>`                                |
| `domain`       | domains, DNS search domains                   | `d-<12 hex>.invalid`                        |
| `ipv4`         | a single IPv4 address                         | an address in `100.64.0.0/10`               |
| `ipv6`         | a single IPv6 address                         | an address in a fixed `/48` of `fd00::/8`   |
| `cidr`         | a network; addresses inside keep their network | same prefix length, in the same ranges      |
| `mac`          | MAC addresses, BSSIDs                         | `02:xx:xx:xx:xx:xx`                         |
| `email`        | e-mail addresses                              | `u-<12 hex>@d-<12 hex>.invalid`             |
| `person`       | names of people; also customers, if they are people | an invented name from a fixed list; a lone word becomes a given name only |
| `iban`         | account numbers                               | same country and length, valid check digits |
| `uuid`         | disk, partition, machine and product UUIDs    | a UUID with version nibble `f`              |
| `hexid`        | 32-digit or `0x`-prefixed 16-digit hex ids: WWN, machine-id | same form, starting `5046` or `0x5046` |
| `fingerprint`  | SSH key fingerprints                          | `SHA256:PF` + 41 letters and digits         |
| `serial`       | serial numbers                                | `PF-<12 upper-case letters and digits>`     |
| `path_segment` | a directory name, replaced inside paths       | `d-<12 hex>`                                |
| `filename`     | a file name; the extension is kept            | `f-<12 hex><ext>`                           |
| `secret`       | anything else                                 | `PF_<12 hex>`                               |

The same value gets the same pseudonym for the whole conversation, another conversation gets other pseudonyms.
The pseudonyms are derived from the secret, not stored anywhere.

### What belongs in the list and what does not

- **Names, not words.** A term is replaced everywhere it appears as a word. A host called `backup` turns
  `rsync --backup` into nonsense for the model, a user called `admin` breaks every `admin` in a config file. Leave
  such entries out, or use a regular expression that matches only the form you mean, such as the host name followed
  by its domain.
- **What the patterns already catch can stay out.** IP addresses, MACs, e-mail addresses, UUIDs, fingerprints and
  labelled serials are detected on their own, and the original plugin's automatic detection with its Gitleaks rules
  catches API keys, tokens, connection strings, phone and ID numbers and bank cards. They belong in the list when the model has to see their structure:
  your networks as `cidr` terms, so that host, gateway and neighbour stay in one network for the model.
- **Addresses that are never replaced.** Loopback, unspecified, broadcast, multicast, link-local and the
  documentation ranges stay as they are, so the model still sees a `bind` to loopback for what it is. Real
  addresses in `100.64.0.0/10` and in the fixed ULA `/48` cannot be terms, because that is where the pseudonyms live;
  the plugin refuses to start with such a term.
- **One file, many machines.** Every machine can add its own block, see the next chapter. The plugin drops exact
  duplicates at start, so a gateway that appears in three blocks is one term.
- **The file is clear text.** It holds exactly the values the plugin exists to keep off the wire. Keep it and its
  backups readable by the proxy's user only, and never paste it into a conversation that runs through the proxy.

`terms` in `config.yaml` takes the same entries in YAML form and is meant for a handful of values; the file is
for the list you maintain.

## Filling the list with machine-ids.py

`machine-ids.py` collects the identifiers of the machine it runs on and writes them in the format above. It needs
nothing but Python 3, reads only local sources, and nothing leaves the machine. Started on a terminal without
options it asks what to do:

```text
$ sudo python3 plugins/machine-ids.py
machine-ids: collects the identifiers of this machine as a term list for the privacyfilter plugin.
Include the other machines of the LAN (mDNS, reverse DNS of the neighbour table)? [y/N]
Include container and VM interfaces (veth, docker, virbr)? [y/N]
Merge into /opt/cliproxyapi/plugins/terms.txt (a backup is written first)? [Y/n]
… host names
… machine-id, boot id, DMI
… network interfaces, DNS, Wi-Fi, Bluetooth
… block devices, USB, battery
… SSH and GPG keys
… user accounts
… done: 93 terms
```

It collects: host name and mDNS name as a regular expression that also matches the name with any domain, the
entries of `/etc/hosts`, machine-id and boot id, DMI product UUID and the serials of board, chassis and product
(root only), every network interface with MAC, permanent MAC, IPv4, IPv6, networks and gateways, DNS servers and
search domains, Wi-Fi SSID and BSSID, Bluetooth adapters, block devices with UUID, PARTUUID, PTUUID, serial, WWN
and label, USB device serials, the battery serial, SSH host keys and the user's own public keys as fingerprints
and key material, GPG key fingerprints, the ZeroTier node id, and local user accounts. Generic account names such
as `admin` or `root` are left out with a note, because they are words. A value that already has the shape of a
pseudonym is written as a comment with the reason.

Options for scripts and for a look before merging:

| Option             | Effect                                                                                     |
|--------------------|--------------------------------------------------------------------------------------------|
| `--stdout`         | print the list, ask nothing                                                                |
| `-o FILE`          | write the list to a file, mode 0600                                                        |
| `--summary`        | print counts per kind only, never a value                                                  |
| `--merge TERMS`    | replace or append this machine's block in an existing term file, numbered backup first     |
| `--lan`            | add the other machines of the LAN: mDNS names via avahi, reverse DNS of the neighbour table |
| `--all-interfaces` | include container and VM interfaces (veth, docker, virbr, ...)                             |

The block of a machine sits between two marker comments that carry its host name. Running the script again on the
same machine replaces that block and leaves the blocks of other machines alone, so the term file of the proxy can
hold every machine you work on: run the script on each machine with `-o`, copy the output to the proxy over `scp`,
and merge it there. Copy it, do not paste it into a conversation. Then restart the proxy.

## Telling the model

The model does see that the values are pseudonyms: `.invalid` is a reserved top-level domain, `100.64.0.0/10` is
the carrier-grade NAT range, a UUID with version nibble `f` exists in no RFC. Left to itself it comments on that,
asks whether the host name is a placeholder, drops the `.invalid`, or "corrects" the value. Tell it once, in the
project's `CLAUDE.md` or in the system prompt, and it stops:

```markdown
Host names like `h-<hex>`, domains like `d-<hex>.invalid`, addresses in `100.64.0.0/10`, MACs starting with
`02:` and similar tokens in this session are pseudonyms that a proxy swaps back to the real values before I see
the answer. Treat them as the real names: use them verbatim, never shorten or "fix" them, never drop the
`.invalid`, never invent new ones in the same shape, and do not comment on their form.
```

## Configuration

The plugin is configured in CLIProxyAPI's `config.yaml` under `plugins.configs.privacyfilter`. The host consumes
`enabled` and `priority`; everything else is passed to the plugin. A complete example:

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
      mode: pseudonymize
      terms_file: terms.txt          # relative to the plugin directory
      terms:                         # a few more, inline
        - {value: example-gmbh.de, kind: domain}
        - {regex: "[a-z0-9-]+\\.home\\.lan", kind: host}
        - {value: markus, kind: person, ignore_case: true}
      path:
        enabled: false               # switch on once the stream restore is confirmed in your setup
      limits:
        mapping_ttl: 30m
      skip_models: []
      skip_formats: []
```

Fields read in both modes:

| Field           | Type   | Default | Description                                                                            |
|-----------------|--------|---------|----------------------------------------------------------------------------------------|
| `mode`          | string | `redact` | `redact` keeps the original one-way behaviour, `pseudonymize` enables reversible pseudonyms and the return path. Both modes run the original detection. |
| `gitleaks_toml` | string | `""`    | Custom gitleaks rule file path. Relative paths are resolved from the plugin directory. Empty uses `rules/gitleaks.toml` next to the library, or the rules embedded at build time. |
| `skip_models`   | array  | `[]`    | Models that bypass the plugin.                                                         |
| `skip_formats`  | array  | `[]`    | Source formats that bypass the plugin.                                                 |

Fields read in `pseudonymize` mode only. With `mode: redact` they are ignored and the plugin behaves byte for byte
like the original:

| Field                    | Type   | Default        | Description                                                                                                                                                                                                                                                                                                               |
|--------------------------|--------|----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `salt_secret_path`       | string | `""`           | HMAC secret file. Empty uses `pseudonym.secret` next to the shared library; a relative path resolves from the plugin directory. At least 32 bytes after trimming; the plugin refuses to start without it.                                                                                                                 |
| `terms`                  | array  | `[]`           | Values to treat as confidential, each `{value: ..., kind: ...}` or `{regex: ..., kind: ...}` with an optional `ignore_case: true`. Takes precedence over every other detection layer.                                                                                                                                       |
| `terms_file`             | string | `""`           | The term list, see [The term list](#the-term-list). A relative path resolves from the plugin directory.                                                                                                                                                                                                                   |
| `patterns`               | object | all on but url | Structural detectors: `ipv4`, `ipv6`, `cidr`, `mac`, `email`, `iban`, `uuid`, `hexid`, `fingerprint`, `serial` default to `true`; `url` is off. `uuid` covers disk and machine UUIDs, `hexid` 32-digit and `0x`-prefixed 16-digit hex ids such as a WWN or machine-id, `fingerprint` SSH host-key fingerprints (`SHA256:…`), `serial` a serial number that follows a label such as `Serial Number:`, `ID_SERIAL_SHORT=`, `"serial":`, `iSerial`, `Seriennummer:` or `s/n:`. |
| `path`                   | object | disabled       | Segment-wise path pseudonymization: `enabled` (default `false`), `replace_unknown` (default `true`, every segment outside the preserve list is replaced; `false` replaces only segments that are also terms), `preserve` (segments added to the built-in list of ordinary directory names such as `home`, `usr`, `src`). |
| `packyme`                | object | enabled        | `enabled` toggles the packyme/privacy-filter layer with the gitleaks rules.                                                                                                                                                                                                                                                |
| `secrets`                | object | disabled       | `enabled` and `rules_toml` for the betterleaks layer. Only effective in a binary built with the `betterleaks` tag; enabling it in a plain build fails registration.                                                                                                                                                         |
| `restore.stream`         | bool   | `true`         | Restore pseudonyms in streamed responses. Non-streamed responses are always restored.                                                                                                                                                                                                                                     |
| `limits.max_body_bytes`  | int    | `33554432`     | Request bodies above this size are rejected.                                                                                                                                                                                                                                                                              |
| `limits.mapping_ttl`     | string | `30m`          | Lifetime of a request's mapping table, measured from the request. Must outlast the longest upstream turnaround.                                                                                                                                                                                                           |
| `on_error`               | string | `block`        | Forward-path behaviour when detection or parsing fails: `block` terminates the request, `passthrough` forwards it unfiltered. The return path always passes through on error.                                                                                                                                             |
| `audit`                  | object | off            | Local audit log: `path` (empty keeps it off; a relative path resolves from the plugin directory) and `max_bytes` (default 10 MiB, the file is rotated once to `.1`). Every mapping and every restore is written in clear text, see [Audit log](#audit-log).                                                             |

## What it does and what it does not do

The plugin replaces values by pseudonyms of the same shape on the way out and puts the originals back on the way in.
It restores what comes back **verbatim**: a pseudonym in running text, in a tool call, in a code block, streamed or
not, with a suffix such as `.bak` or `-backup.tar.gz` glued to it, written in upper case, or, for a domain or an
e-mail address, without the reserved `.invalid` that a model recognises as a marker and drops. It does not restore
what the model **derives** from a pseudonym, because a derived value is in no mapping table:

- The model cannot compute with a pseudonym. "The next address after X" is computed on the pseudonym and comes back
  as the pseudonym's neighbour, not the original's. A configured network is the exception: addresses inside it keep
  their network, so "the same /24" holds, and arithmetic that lands on an address the request carried comes back.
- A partial pseudonym is not restored: the last four characters of a token, a prefix with a wildcard, a token cut
  in the middle. Nor is a pseudonym the model invented from the pattern of others, such as a name for a new file.
- The model does not know what a pseudonym stands for. It cannot tell an Intel NUC from a Raspberry Pi by the
  name `h-e2ba…`, and it will call a `100.64.0.0/10` address a carrier-grade NAT address. Every conclusion it
  draws from the value itself, rather than from the context, is drawn from the wrong value.
- A term of the list is replaced everywhere it appears as a word, see [What belongs in the list](#what-belongs-in-the-list-and-what-does-not).
- Loopback, unspecified, broadcast, multicast, link-local and the documentation addresses are never replaced.
- Thinking blocks and tool names are never touched in either direction.

The mapping lives in memory for one request and is derived, not stored: the same value gets the same pseudonym
throughout one conversation, another conversation gets other pseudonyms. Nothing about the mapping leaves the
process, and nothing is written to disk unless `audit.path` is set. A conversation that starts with the real value
in the first message and continues with the pseudonym in later messages is fine; only the direction matters, and
both directions are handled.

### Known limits

- Only the Anthropic Messages schema is handled on the return path today; the plugin logs a warning and passes other
  formats through unchanged. Register it with `skip_formats` for those formats if you want no forward filtering
  either.
- Thinking blocks are never touched in either direction. Their signature is bound to the text, so a summary in
  the client's thinking view shows the pseudonyms, not the originals.
- A person pseudonym for a lone surname is rendered as a given name, so a surname used on its own may read as a
  second given name in the model's answer.
- A term matches at word boundaries, and the underscore is a boundary: `nuc_old` and `NUC_HOST` contain the host
  `nuc`. Letters and digits bind, so `nucleus` does not.
- Addresses outside every configured network are spread over the whole marker range without any relation to each
  other. Add your networks as `cidr` terms if the model has to reason about them.
- The original values are in memory in clear text while the request is alive, as they have to be for the
  restore.
- A real address in `100.64.0.0/10` or a ULA network that happens to match the fixed `/48` cannot be
  pseudonymized. The plugin refuses to start with such a term. A term that equals one of the built-in person
  names is fine: that entry is left out of the name list for this plugin, a warning with the count is logged,
  and the other person pseudonyms stay as they are.
- `path.enabled` defaults to `false`. Switch it on after you have seen the stream restore work in your setup: a
  half-restored path in a tool call does more harm than a leaked one.
- The betterleaks layer exists only in a build with the `betterleaks` tag, which roughly triples the size of the
  shared library.
- A serial number is only detected behind a label. A bare serial in running text, a git commit hash, an image
  digest or a DNS zone serial are left alone on purpose, so a serial printed without any label reaches the
  model unchanged. Add it to the term list if it matters.
- With `path.enabled`, the model sees every file name as `f-<12 hex><ext>`. When it creates a new file it tends
  to pick a name of the same shape, which is in no mapping table and reaches the client as is. Rename the file;
  the content is restored normally.

## Building from source

Requirements: Go 1.26 or newer, CGO enabled, `make`.

```bash
git clone https://github.com/rheodev/cpa-plugin-privacyfilter.git
cd cpa-plugin-privacyfilter
make build
```

The default build writes the shared library to the repository root, `privacyfilter.so` on Linux,
`privacyfilter.dylib` on macOS, `privacyfilter.dll` on Windows. Build for a specific platform with `GOOS` and
`GOARCH`, and use `BUILD_DIR` to place the output elsewhere; then `machine-ids.py` is copied next to it:

```bash
GOOS=linux GOARCH=amd64 BUILD_DIR=dist make build
GOOS=darwin GOARCH=arm64 make build
GOOS=windows GOARCH=amd64 make build
```

`build/build.sh` builds the same library for `linux/amd64` inside a `golang:1.26-bookworm` container with Podman, so
the result loads in a `debian:bookworm-slim` image regardless of the glibc on the build machine. It honours
`BUILD_TAGS` and `VERSION` and writes both files to `dist/`:

```bash
build/build.sh 0.4.6
```

Include the betterleaks credential scanner (see [betterleaks](#betterleaks)); the plain build does not link it:

```bash
BUILD_TAGS=betterleaks make build
```

Plugin metadata: name `privacyfilter`, capability `RequestInterceptor`, in `pseudonymize` mode also
`ResponseInterceptor`, `StreamChunkInterceptor` and `RequestCompletion`, schema version 3, author `rheodev`.

## How it works inside

### Pseudonyms

Pseudonyms are `HMAC-SHA256(secret || salt, kind || value || attempt)` rendered per kind. The salt is derived once
per conversation from the `X-Claude-Code-Session-Id` header, then from `metadata.user_id`, and finally from a hash
of the first message, so a follow-up request produces the same pseudonyms as the previous one and the model's
context stays coherent. Nothing is random and nothing is stored on disk: the mapping table lives in memory for the
lifetime of one request and is released on request completion or after `mapping_ttl`.

A network given as a `cidr` term maps to a network of the same prefix length inside the marker range. Every
address inside it is rendered into that network, only the host bits come from the address's own digest, and a
network inside another configured network lies inside that one's pseudonym. Host, gateway and neighbour stay
related for the model. Addresses outside every configured network are spread over the whole range.

Pseudonym shapes are chosen so that no real value can look like one: `100.64.0.0/10` is the carrier-grade NAT
range, `02:` MACs are locally administered, `.invalid` is reserved by RFC 2606, the UUID version nibble `f` exists
in no RFC 9562 version, the IBAN bank code starts with four zeros no issuer hands out, hex ids start with `5046`,
serials with `PF-`, secrets with `PF_`. Person pseudonyms come from a fixed list of invented names; a term that
equals one of them drops that entry from the list.

### Forward and return path

The forward path walks every string of the JSON body except those on a deny list (identifiers, tool names, model
names, thinking blocks and their signatures) and runs the detection layers in fixed order: the term list, the
structural patterns, the path layer, the original plugin's detection (packyme with the Gitleaks rules), betterleaks.
Overlapping hits are merged, the longest wins. A hit of the original detection is pseudonymized by kind: an
e-mail address as `email`, an IP address as `ipv4` or `ipv6`, everything else, secrets, phone and ID numbers, bank
cards, as an opaque `secret` token that is restored like any other pseudonym. The
return path scans the response body in one pass over the same deny list and swaps pseudonyms back only at token
boundaries, so a pseudonym embedded in a longer identifier is left alone.

Streamed responses are restored chunk by chunk. Because a pseudonym may be split across two deltas, the plugin
holds back the tail of the text that could still grow into a pseudonym, restores a pseudonym that is complete
and cannot grow right away, and flushes the held tail as a synthetic delta before the block or the message ends.
Splitting at every byte position is covered by the tests, including a pseudonym whose last byte could begin
another one.

### Audit log

`audit.path` switches on a per-request log next to the shared library (or wherever the path points). It is meant
for checking what the plugin did with a request, not for permanent operation: every line is clear text, so the
file holds exactly the values the plugin exists to keep off the wire. The file is created with mode `0600`, the
plugin logs a warning at start-up while the option is set, and the file is rotated once to `.1` at `max_bytes`.
Lines are tab-separated, one record per line:

```text
<time>  request   <request id>  format=claude  session=header  body=<bytes>  out=<bytes>  distinct=<n>
<time>  map       <request id>  <kind>  <original>  <pseudonym>
<time>  restored  <request id>  <pseudonym>  <original>  <count>
<time>  complete  <request id>  outcome=succeeded  stream=true  restored_distinct=<n>  restored_total=<n>
```

`map` lines list the whole mapping table of the request sorted by kind and value, `restored` lines the
pseudonyms that actually came back in the response with how often each was swapped. A value that was detected
but never returned appears in `map` only. Values that were redacted rather than pseudonymized do not appear in
this log; they stay in the ordinary plugin log as before.

### Redact mode

`mode: redact`, the default, is the original plugin: one-way, nothing comes back. It runs for both before-auth and
after-auth request interception hooks, then parses the JSON body:

1. Checks `skip_models` and `skip_formats`.
2. Parses the request body as JSON.
3. Handles `messages` first, then falls back to `input`.
4. Edits text fields only.
5. Replaces detected sensitive data with placeholders.
6. Leaves the request unchanged if parsing fails or no supported field is found.

Supported request shapes include OpenAI-style `messages` and `input` bodies:

```json
{
  "model": "gpt-4",
  "messages": [
    {
      "role": "user",
      "content": "Email me at user@example.com"
    }
  ]
}
```

```json
{
  "model": "gpt-4",
  "input": "My GitHub token is ghp_xxx"
}
```

Detection in both modes uses [packyme/privacy-filter](https://github.com/packyme/privacy-filter) with Gitleaks
rules for secrets, connection strings, certificates and similar data. The rules are embedded at build time from
`rules/gitleaks.toml`; at runtime the plugin takes `gitleaks_toml` from the configuration if set, else a
`rules/gitleaks.toml` sidecar next to the shared library, else the embedded rules. Update the embedded rules with
`make update-rules` and rebuild.

### betterleaks

[betterleaks](https://github.com/betterleaks/betterleaks) is a gitleaks fork with a larger rule set. It is
compiled in only with `BUILD_TAGS=betterleaks` and switched on with `secrets.enabled: true`. Its credential
validation, which would send found credentials to their providers over HTTP, is disabled in every build and
cannot be enabled by configuration. `secrets.rules_toml` points to a custom rules file; empty uses the embedded
rules. A rules file that does not compile fails registration instead of taking the proxy down.

## Development

```bash
go test ./...
go test -tags betterleaks ./...
make build
make clean
```

Main files:

```text
main.go                 Plugin metadata, registration and build entry
abi.go                  CLIProxyAPI plugin ABI adapter
interceptor.go          Request interception: redact and pseudonymize forward paths
response.go             Return path for non-streamed responses
stream.go               Return path for streamed responses, holdback and flush
lifecycle.go            Request completion, releases the mapping table
config.go               YAML configuration parsing
termsfile.go            Term list file format
detect/                 Detection layers: terms, patterns, paths, packyme, betterleaks
pseudo/                 HMAC pseudonyms, renderers per kind, salt and secret handling
mapping/                Request-scoped mapping tables and the restorer
payload/                JSON walking, deny list, Anthropic SSE events
tools/machine-ids.py    Collects this machine's identifiers as a term file; copied to dist/ by the build
cmd/termsgen/           Older generator: a term file from ssh config and hosts
internal/leaktest/      End-to-end leak test: nothing confidential survives the forward path
rules/gitleaks.toml     Built-in detection rules
```

Dependency note:

```text
privacyfilter => github.com/packyme/privacy-filter
```

## Credits

- Core filtering logic: [packyme/privacy-filter](https://github.com/packyme/privacy-filter)
- Plugin runtime: [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
- AI learners and builders can join the Linux.do community: [linux.do](https://linux.do/)
