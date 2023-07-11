// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/pflag"
	"github.com/tillitis/tkeyclient"
	"github.com/tillitis/tkeysign"
	"github.com/tillitis/tkeyutil"
)

// nolint:typecheck // Avoid lint error when the embedding file is missing.
// Build copies the built signer here
//
//go:embed signer.bin
var signerBinary []byte

// Use when printing err/diag msgs
var le = log.New(os.Stderr, "", 0)

// May be set to non-empty at build time to indicate that the signer
// app has been compiled with touch requirement removed.
var signerAppNoTouch string

const (
	// 4 chars each.
	wantFWName0  = "tk1 "
	wantFWName1  = "mkdf"
	wantAppName0 = "tk1 "
	wantAppName1 = "sign"
)

func isFirmwareMode(tk *tkeyclient.TillitisKey) bool {
	nameVer, err := tk.GetNameVersion()
	if err != nil {
		return false
	}
	// not caring about nameVer.Version
	return nameVer.Name0 == wantFWName0 &&
		nameVer.Name1 == wantFWName1
}

func isWantedApp(signer tkeysign.Signer) bool {
	nameVer, err := signer.GetAppNameVersion()
	if err != nil {
		if !errors.Is(err, io.EOF) {
			le.Printf("GetAppNameVersion: %s\n", err)
		}
		return false
	}

	// not caring about nameVer.Version
	return nameVer.Name0 == wantAppName0 &&
		nameVer.Name1 == wantAppName1
}

// signFile returns Ed25519 signature
func signFile(signer tkeysign.Signer, pubkey []byte, fileName string) ([]byte, error) {
	message, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", fileName, err)
	}

	fileDigest := sha512.Sum512(message)
	le.Printf("SHA512 hash: %x\n", fileDigest)

	if signerAppNoTouch == "" {
		le.Printf("The TKey will flash green when touch is required ...\n")
	} else {
		le.Printf("WARNING! This tkey-sign and signer app is built with the touch requirement removed\n")
	}

	signature, err := signer.Sign(fileDigest[:])
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	if !ed25519.Verify(pubkey, fileDigest[:], signature) {
		return nil, fmt.Errorf("signature FAILED verification")
	}

	return signature, nil
}

// fileInputToHex reads inputFile and returns a trimmed slice decoded to hex.
func fileInputToHex(inputFile string) ([]byte, error) {
	input, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", inputFile, err)
	}

	input = bytes.Trim(input, "\n")
	hexOutput := make([]byte, hex.DecodedLen(len(input)))
	_, err = hex.Decode(hexOutput, input)
	if err != nil {
		return nil, fmt.Errorf("could not decode: %w", err)
	}
	return hexOutput, nil
}

// verifySignature verifies a Ed25519 signature from input files of message, signature and public key
func verifySignature(fileMessage string, fileSignature string, filePubkey string) error {
	signature, err := fileInputToHex(fileSignature)
	if err != nil {
		return fmt.Errorf("decodeFileInput: %w", err)
	}

	if len(signature) != 64 {
		return fmt.Errorf("invalid length of signature. Expected 64 bytes, got %d bytes", len(signature))
	}

	pubkey, err := fileInputToHex(filePubkey)
	if err != nil {
		return fmt.Errorf("decodeFileInput: %w", err)
	}

	if len(pubkey) != 32 {
		return fmt.Errorf("invalid length of public key. Expected 32 bytes, got %d bytes", len(pubkey))
	}

	fmt.Printf("Public key: %x\n", pubkey)
	fmt.Printf("Signature: %x\n", signature)

	message, err := os.ReadFile(fileMessage)
	if err != nil {
		return fmt.Errorf("could not read %s: %w", fileMessage, err)
	}

	digest := sha512.Sum512(message)
	le.Printf("SHA512 hash: %x\n", digest)

	if !ed25519.Verify(pubkey, digest[:], signature) {
		return fmt.Errorf("signature not valid")
	}

	return nil
}

// doSign connects to a TKey and signs the attached file
func doSign(devPath string, verbose bool, fileName string, fileUSS string, enterUSS bool, showPubkeyOnly bool, speed int) error {
	if !verbose {
		tkeyclient.SilenceLogging()
	}

	if devPath == "" {
		var err error
		devPath, err = tkeyclient.DetectSerialPort(true)
		if err != nil {
			return fmt.Errorf("DetectSerialPort: %w", err)
		}
	}

	tk := tkeyclient.New()
	le.Printf("Connecting to TKey on serial port %s ...\n", devPath)
	if err := tk.Connect(devPath, tkeyclient.WithSpeed(speed)); err != nil {
		return fmt.Errorf("could not open %s: %w", devPath, err)
	}

	if isFirmwareMode(tk) {
		var secret []byte
		var err error

		if enterUSS {
			secret, err = tkeyutil.InputUSS()
			if err != nil {
				return fmt.Errorf("InputUSS: %w", err)
			}
		}
		if fileUSS != "" {
			secret, err = tkeyutil.ReadUSS(fileUSS)
			if err != nil {
				return fmt.Errorf("ReadUSS: %w", err)
			}
		}

		if err := tk.LoadApp(signerBinary, secret); err != nil {
			return fmt.Errorf("couldn't load signer: %w", err)
		}

		le.Printf("Signer app loaded.\n")
	} else {
		if enterUSS || fileUSS != "" {
			le.Printf("WARNING: App already loaded, your USS won't be used.")
		} else {
			le.Printf("WARNING: App already loaded.")
		}
	}

	signer := tkeysign.New(tk)
	defer signer.Close()

	handleSignals(func() { os.Exit(1) }, os.Interrupt, syscall.SIGTERM)

	if !isWantedApp(signer) {
		return fmt.Errorf("no TKey on the serial port, or it's running wrong app (and is not in firmware mode)")
	}

	pubkey, err := signer.GetPubkey()
	if err != nil {
		return fmt.Errorf("GetPubKey failed: %w", err)
	}
	if showPubkeyOnly {
		fmt.Printf("%x\n", pubkey)
		return nil
	}
	le.Printf("Public Key from TKey: %x\n", pubkey)

	signature, err := signFile(signer, pubkey, fileName)
	if err != nil {
		return fmt.Errorf("signing faild: %w", err)
	}

	le.Printf("Signature over message by TKey (on stdout):\n")
	fmt.Printf("%x\n", signature)

	return nil
}

func handleSignals(action func(), sig ...os.Signal) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sig...)
	go func() {
		for {
			<-ch
			action()
		}
	}()
}

func main() {
	var fileName, fileUSS, fileSignature, filePubkey, devPath string
	var speed int
	var enterUSS, showPubkeyOnly, verbose, helpOnlySign, helpOnlyVerify bool

	signString := "sign"
	verifyString := "verify"

	// Default text to show
	root := pflag.NewFlagSet("root", pflag.ExitOnError)
	root.Usage = func() {
		desc := fmt.Sprintf(`%[1]s signs the data provided in FILE (the "message")
using the Tillitis TKey. The message will be hashed using
SHA512 and signed with Ed25519 using the TKey's private key.

It is also possible to verify signatures with this tool, provided
the message, signature and public key.

Usage:
  %[1]s <command> [flags] FILE...

Commands:
  sign        Create a signature
  verify      Verify a signature

Use <command> --help for further help, i.e. %[1]s verify --help`, os.Args[0])
		le.Printf("%s\n\n%s", desc,
			root.FlagUsagesWrapped(86))
	}

	// Flag for command "sign"
	cmdSign := pflag.NewFlagSet(signString, pflag.ExitOnError)
	cmdSign.SortFlags = false
	cmdSign.BoolVarP(&showPubkeyOnly, "show-pubkey", "p", false,
		"Don't sign anything, only output the public key.")
	cmdSign.StringVar(&devPath, "port", "",
		"Set serial port device `PATH`. If this is not passed, auto-detection will be attempted.")
	cmdSign.IntVar(&speed, "speed", tkeyclient.SerialSpeed,
		"Set serial port speed in `BPS` (bits per second).")
	cmdSign.BoolVar(&enterUSS, "uss", false,
		"Enable typing of a phrase to be hashed as the User Supplied Secret. The USS is loaded onto the TKey along with the app itself. A different USS results in different public/private keys, meaning a different identity.")
	cmdSign.StringVar(&fileUSS, "uss-file", "",
		"Read `FILE` and hash its contents as the USS. Use '-' (dash) to read from stdin. The full contents are hashed unmodified (e.g. newlines are not stripped).")
	cmdSign.BoolVar(&verbose, "verbose", false, "Enable verbose output.")
	cmdSign.BoolVarP(&helpOnlySign, "help", "h", false, "Output this help.")
	cmdSign.Usage = func() {
		desc := fmt.Sprintf(`Usage: %[1]s sign [flags...] FILE

  Signs the data provided in FILE (the "message"). The message will be
  hashed with SHA512 and signed with Ed25519 using the TKey's private key.

  The signature is always output on stdout. Exit status code is 0 if everything
  went well and the signature can be verified using the public key. Otherwise
  exit code is non-zero.

  Alternatively, --show-pubkey can be used to only output (on stdout) the
  public key of the signer app on the TKey.`, os.Args[0])
		le.Printf("%s\n\n%s", desc,
			cmdSign.FlagUsagesWrapped(86))
	}

	// Flag for command "verify"
	cmdVerify := pflag.NewFlagSet(verifyString, pflag.ExitOnError)
	cmdVerify.SortFlags = false
	cmdVerify.BoolVarP(&helpOnlyVerify, "help", "h", false, "Output this help.")
	cmdVerify.Usage = func() {
		desc := fmt.Sprintf(`Usage: %[1]s verify FILE SIG-FILE PUBKEY-FILE

  Verifies wheather the Ed25519 signature of the message is valid
  using the public key. Does not need a connected TKey to verify.

  SIG-FILE is expected to be an 64 bytes Ed25519 signature in hex.
  PUBKEY-FILE is expected to be an 64 bytes Ed25519 public key in hex.

  The return value is 0 if the signature is valid, otherwise non-zero.
  Newlines will be striped from the input files. `, os.Args[0])
		le.Printf("%s\n\n%s", desc,
			cmdVerify.FlagUsagesWrapped(86))
	}

	if len(os.Args) == 1 {
		root.Usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case signString:
		if err := cmdSign.Parse(os.Args[2:]); err != nil {
			le.Printf("Error parsing input arguments: %v\n", err)
			os.Exit(2)
		}

		if helpOnlySign {
			cmdSign.Usage()
			os.Exit(0)
		}

		if cmdSign.NArg() > 0 {
			if cmdSign.NArg() > 1 {
				le.Printf("Unexpected argument: %s\n\n", strings.Join(cmdSign.Args()[1:], " "))
				cmdSign.Usage()
				os.Exit(2)
			}
			fileName = cmdSign.Args()[0]
		}

		if fileName == "" && !showPubkeyOnly {
			le.Printf("Please pass at least a message FILE, or -p.\n\n")
			cmdSign.Usage()
			os.Exit(2)
		}

		if fileName != "" && showPubkeyOnly {
			le.Printf("Pass only a message FILE or -p.\n\n")
			cmdSign.Usage()
			os.Exit(2)
		}

		if enterUSS && fileUSS != "" {
			le.Printf("Pass only one of --uss or --uss-file.\n\n")
			cmdSign.Usage()
			os.Exit(2)
		}

		err := doSign(devPath, verbose, fileName, fileUSS, enterUSS, showPubkeyOnly, speed)
		if err != nil {
			le.Printf("Error signing: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)

	case verifyString:
		if err := cmdVerify.Parse(os.Args[2:]); err != nil {
			le.Printf("Error parsing input arguments: %v\n", err)
			os.Exit(2)
		}

		if helpOnlyVerify {
			cmdVerify.Usage()
			os.Exit(0)
		}

		if cmdVerify.NArg() < 3 {
			le.Printf("Missing %d input file(s) to verify signature.\n\n", 3-cmdVerify.NArg())
			cmdVerify.Usage()
			os.Exit(2)
		} else if cmdVerify.NArg() > 3 {
			le.Printf("Unexpected argument: %s\n\n", strings.Join(cmdVerify.Args()[3:], " "))
			cmdVerify.Usage()
			os.Exit(2)
		}
		fileName = cmdVerify.Args()[0]
		fileSignature = cmdVerify.Args()[1]
		filePubkey = cmdVerify.Args()[2]

		le.Printf("Verifying signature ...\n")
		if err := verifySignature(fileName, fileSignature, filePubkey); err != nil {
			le.Printf("Error verifying: %v\n", err)
			os.Exit(1)
		}
		le.Printf("Signature verified.\n")
		os.Exit(0)

	default:
		root.Usage()
		le.Printf("%q is not a valid subcommand.\n", os.Args[1])
		os.Exit(2)
	}
	os.Exit(1) // should never be reached
}
