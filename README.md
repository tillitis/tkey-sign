
[![ci](https://github.com/tillitis/tkey-sign/actions/workflows/ci.yaml/badge.svg?branch=main&event=push)](https://github.com/tillitis/tkey-sign/actions/workflows/ci.yaml)

# tkey-sign

`tkey-sign` is a command to do a cryptographic signature (ed25519)
over a file using the [Tillitis](https://tillitis.se/) TKey. It uses
the [signer device
app](https://github.com/tillitis/tkey-device-signer) for the actual
signatures.

It is currently just a test tool and can take at most 4 kiB large
files.

See [Release notes](RELEASE.md).

### Usage

You need the tkey-runapp from [the apps
repo](https://github.com/tillitis/tillitis-key1-apps) the and the
[`signer`](https://github.com/tillitis/tkey-device-signer). Build them
first.

Then:

```
$ tkey-runapp [flags...] [path-to-signer-app]
$ tkey-sign [flags...] [FILE]

```

Options are:

```
  -p, --show-pubkey   Don't sign anything, only output the public key.
      --port PATH     Set serial port device PATH. If this is not passed,
                      auto-detection will be attempted.
      --speed BPS     Set serial port speed in BPS (bits per second). (default 62500)
      --verbose       Enable verbose output.
      --help          Output this help.
```

## Building

You have two options, either our OCI image
`ghcr.io/tillitis/tkey-builder` for use with a rootless podman setup,
or native tools.

### Building with Podman

We provide an OCI image with all tools you can use to build the
tkey-libs and the apps. If you have `make` and Podman installed you
can us it like this in the `tkey-libs` directory and then this
directory:

```
make podman
```

and everything should be built. This assumes a working rootless
Podman. On Ubuntu 22.10, running
```
apt install podman rootlesskit slirp4netns
```

should be enough to get you a working Podman setup.

### Building with host tools

You need `golang` and `make`.

```
$ make
```

## Licenses and SPDX tags

Unless otherwise noted, the project sources are licensed under the
terms and conditions of the "GNU General Public License v2.0 only":

> Copyright Tillitis AB.
>
> These programs are free software: you can redistribute it and/or
> modify it under the terms of the GNU General Public License as
> published by the Free Software Foundation, version 2 only.
>
> These programs are distributed in the hope that it will be useful,
> but WITHOUT ANY WARRANTY; without even the implied warranty of
> MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
> General Public License for more details.

> You should have received a copy of the GNU General Public License
> along with this program. If not, see:
>
> https://www.gnu.org/licenses

See [LICENSE](LICENSE) for the full GPLv2-only license text.

External source code we have imported are isolated in their own
directories. They may be released under other licenses. This is noted
with a similar `LICENSE` file in every directory containing imported
sources.

The project uses single-line references to Unique License Identifiers
as defined by the Linux Foundation's [SPDX project](https://spdx.org/)
on its own source files, but not necessarily imported files. The line
in each individual source file identifies the license applicable to
that file.

The current set of valid, predefined SPDX identifiers can be found on
the SPDX License List at:

https://spdx.org/licenses/
