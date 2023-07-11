
[![ci](https://github.com/tillitis/tkey-sign/actions/workflows/ci.yaml/badge.svg?branch=main&event=push)](https://github.com/tillitis/tkey-sign/actions/workflows/ci.yaml)

# tkey-sign

`tkey-sign` is a utility that can do and verify an Ed25519
cryptographic signature over a digest of a file using the
[Tillitis](https://tillitis.se/) TKey. It uses the [signer device
app](https://github.com/tillitis/tkey-device-signer) for the actual
signatures.

It can also verify a signature by passing files with the message,
signature, and the public key as arguments.

See [Release notes](RELEASE.md).

## Usage

```
$ tkey-sign <command> [flags...] FILE...
```

Commands are:
```
  sign        Create a signature
  verify      Verify a signature
```

Usage for the sign-command are:
```
$ tkey-sign sign [flags...] FILE
```
with options:

```
  -p, --show-pubkey     Don't sign anything, only output the public key.
      --port PATH       Set serial port device PATH. If this is not passed,
                        auto-detection will be attempted.
      --speed BPS       Set serial port speed in BPS (bits per second). (default
                        62500)
      --uss             Enable typing of a phrase to be hashed as the User
                        Supplied Secret. The USS is loaded onto the TKey along
                        with the app itself. A different USS results in
                        different public/private keys, meaning a different identity.
      --uss-file FILE   Read FILE and hash its contents as the USS. Use '-'
                        (dash) to read from stdin. The full contents are hashed
                        unmodified (e.g. newlines are not stripped).
      --verbose         Enable verbose output.
  -h, --help            Output this help.
```

Usage for the verify-command are:
```
$ tkey-sign verify FILE SIG-FILE PUBKEY-FILE
```

## Building

You have two options, either our OCI image
`ghcr.io/tillitis/tkey-builder` for use with a rootless podman setup,
or native tools.

With native tools you should be able to use our build script:

```
$ ./build.sh
```

which also clones and builds the [TKey device
libraries](https://github.com/tillitis/tkey-libs) and the [signer
device app](https://github.com/tillitis/tkey-device-signer) first.

If you want to do it manually please inspect the build script, but
basically you clone the `tkey-libs` and `tkey-device-signer` repos,
build the signer, copy it to `signer.bin` here and then `make`.

You can install `tkey-sign` and reload the udev rules to get access to
the TKey with:

```
$ sudo make install
$ sudo reload-rules
```

### Building with Podman

We provide an OCI image with all tools you can use to build the
tkey-libs and the apps.

Like above you need to clone `tkey-libs` and the `tkey-device-signer`
first. This repo and those have `podman` targets. So `make podman`
should work in all of them. Be sure to copy the signer to this repo
before building here.

This assumes a working rootless Podman. On Ubuntu 22.10, running

```
apt install podman rootlesskit slirp4netns
```

should be enough to get you a working Podman setup.

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
