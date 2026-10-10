package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/eluvane/ariad/bindings/go"
)

const (
	timeoutMS   = uint32(10000)
	echoPayload = "ping"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: echo <endpoint-ip:port> <tls-name> <ca.der> <echo-destination>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3], os.Args[4]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("go_h2_echo=ok bytes=%d\n", len(echoPayload))
}

func readRoot(path string) ([]byte, error) {
	// #nosec G304 G703 -- The local CLI host selects its own trust-root file.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	root, readErr := io.ReadAll(io.LimitReader(file, int64(ariad.MaxTrustRootDERBytes)+1))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, err
	}
	if len(root) == 0 || len(root) > ariad.MaxTrustRootDERBytes {
		return nil, fmt.Errorf("trust root must contain 1..%d DER bytes", ariad.MaxTrustRootDERBytes)
	}
	return root, nil
}

func wipeCredential(credential []byte) {
	for i := range credential {
		credential[i] = 0
	}
}

func run(endpoint, identity, rootPath, destination string) (err error) {
	credentialHex := os.Getenv("ARIAD_CREDENTIAL_HEX")
	credentialError := fmt.Errorf("ARIAD_CREDENTIAL_HEX must contain exactly %d hexadecimal digits", ariad.CredentialHexBytes)
	if len(credentialHex) != ariad.CredentialHexBytes {
		return credentialError
	}
	credential, err := hex.DecodeString(credentialHex)
	defer wipeCredential(credential)
	if err != nil || len(credential) != ariad.CredentialBytes {
		return credentialError
	}
	root, err := readRoot(rootPath)
	if err != nil {
		return err
	}
	engine, err := ariad.NewEngine(endpoint, identity, root)
	if err != nil {
		return err
	}
	defer func() {
		forced, cleanupErr := engine.Destroy(timeoutMS)
		if forced {
			fmt.Fprintln(os.Stderr, "engine cleanup was forced; admitted calls may retain runtime cleanup")
		}
		err = errors.Join(err, cleanupErr)
	}()
	session, err := engine.Connect(credential, timeoutMS)
	wipeCredential(credential)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, session.Destroy()) }()
	stream, err := session.OpenStream(destination, timeoutMS)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, stream.Destroy()) }()
	payload := []byte(echoPayload)
	reply := make([]byte, len(payload))
	for offset := 0; offset < len(payload); {
		accepted, writeErr := stream.Write(payload[offset:], timeoutMS)
		if writeErr != nil {
			return writeErr
		}
		for received := 0; received < accepted; {
			count, readErr := stream.Read(reply[received:accepted], timeoutMS)
			if readErr != nil {
				return readErr
			}
			received += count
		}
		if !bytes.Equal(reply[:accepted], payload[offset:offset+accepted]) {
			return errors.New("echo mismatch")
		}
		offset += accepted
	}
	if endErr := stream.EndWrite(timeoutMS); endErr != nil {
		return endErr
	}
	if _, err = stream.Read(reply, timeoutMS); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("expected clean stream EOF")
	}
	forced, err := session.Close(ariad.CloseGraceful, timeoutMS)
	if err != nil {
		return err
	}
	if forced {
		return errors.New("session closure was forced")
	}
	return nil
}
