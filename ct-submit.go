// Copyright (c) 2015-2016 Graham Edgecombe <gpe@grahamedgecombe.com>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package main

import (
	"bytes"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type addChain struct {
	Chain []string `json:"chain"`
}

type signedCertificateTimestamp struct {
	Version    uint8  `json:"sct_version"`
	LogID      string `json:"id"`
	Timestamp  int64  `json:"timestamp"`
	Extensions string `json:"extensions"`
	Signature  string `json:"signature"`
}

func (sct signedCertificateTimestamp) Write(w io.Writer) error {
	// Version
	if err := binary.Write(w, binary.BigEndian, sct.Version); err != nil {
		return err
	}

	// LogID
	bytes, err := base64.StdEncoding.DecodeString(sct.LogID)
	if err != nil {
		return err
	}

	_, err = w.Write(bytes)
	if err != nil {
		return err
	}

	// Timestamp
	if err := binary.Write(w, binary.BigEndian, sct.Timestamp); err != nil {
		return err
	}

	// Extensions
	bytes, err = base64.StdEncoding.DecodeString(sct.Extensions)
	if err != nil {
		return err
	}

	length := len(bytes)
	if length > 65535 {
		return errors.New("extensions are too long")
	}

	if err := binary.Write(w, binary.BigEndian, uint16(length)); err != nil {
		return err
	}

	_, err = w.Write(bytes)
	if err != nil {
		return err
	}

	// Signature
	bytes, err = base64.StdEncoding.DecodeString(sct.Signature)
	if err != nil {
		return err
	}

	_, err = w.Write(bytes)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	// parse args
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, `usage: ct-submit <log server>

ct-submit reads a PEM-encoded X.509 certificate chain from stdin and submits it
to the given Certificate Transparency log server. The Signed Certificate
Timestamp structure returned by the log server is written to stdout in binary.

The leaf certificate should be the first certificate in the chain, followed by
any intermediate certificates and, optionally, the root certificate.

The signature of the SCT is not verified.
`)
		os.Exit(1)
	}

	logServer := os.Args[1]

	// read certificate chain from stdin
	in, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	msg := addChain{}
	for {
		block, remaining := pem.Decode(in)
		in = remaining

		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		msg.Chain = append(msg.Chain, base64.StdEncoding.EncodeToString(block.Bytes))
	}

	// construct add-chain message
	payload, err := json.Marshal(msg)
	if err != nil {
		panic(err)
	}

	// construct add-chain URL
	if !strings.Contains(logServer, "://") {
		logServer = "https://" + logServer
	}

	if !strings.HasSuffix(logServer, "/") {
		logServer = logServer + "/"
	}

	addChainURL, err := url.Parse(logServer)
	if err != nil {
		panic(err)
	}

	addChainURL, err = addChainURL.Parse("ct/v1/add-chain")
	if err != nil {
		panic(err)
	}

	// send add-chain message to the log
	response, err := http.Post(addChainURL.String(), "application/json", bytes.NewReader(payload))
	if err != nil {
		panic(err)
	}

	if response.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "unexpected status %s from log server:\n\n", response.Status)
		io.Copy(os.Stderr, response.Body)
		os.Exit(1)
	}

	// decode JSON SCT structure
	payload, err = ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}

	sct := signedCertificateTimestamp{}
	if err = json.Unmarshal(payload, &sct); err != nil {
		panic(err)
	}

	// write binary SCT structure to stdout
	if err = sct.Write(os.Stdout); err != nil {
		panic(err)
	}
}
