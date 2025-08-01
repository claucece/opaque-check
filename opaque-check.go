// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package opaque implements OPAQUE, an asymmetric password-authenticated key exchange protocol that is secure against
// pre-computation attacks. It enables a client to authenticate to a server without ever revealing its password to the
// server. Protocol details can be found on the IETF RFC page (https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque)
// and on the GitHub specification repository (https://github.com/cfrg/draft-irtf-cfrg-opaque).
package opaque

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"io"
	"log"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ksf"
	"github.com/claucece/opaque-check/internal"
	"github.com/claucece/opaque-check/internal/encoding"
	"github.com/claucece/opaque-check/internal/keyrecovery"
	"github.com/claucece/opaque-check/internal/oprf"
	"github.com/claucece/opaque-check/internal/tag"
	"golang.org/x/crypto/hkdf"
)

const (
	// seedLength is the default length used for seeds.
	seedLength = oprf.SeedLength
)

// Deserializer exposes the message deserialization functions.
type Deserializer struct {
	conf *internal.Configuration
}

// Server represents an abridged OPAQUE Server, exposing its functions and holding its state.
type Server struct {
	Deserialize *Deserializer
	conf        *internal.Configuration
}

// Client represents an abridged OPAQUE Client, exposing its functions and holding its state.
type Client struct {
	Deserialize *Deserializer
	OPRF        *oprf.Client
	conf        *internal.Configuration
}

// RegistrationRecord represents the client record sent as the last registration message by the client to the server.
type RegistrationRecord struct {
	PublicKey  *ecc.Element `json:"clientPublicKey"`
	MaskingKey []byte       `json:"maskingKey"`
	Envelope   []byte       `json:"envelope"`
}

// suffixString returns the concatenation of the input byte string and the string argument.
func suffixString(a []byte, b string) []byte {
	e := make([]byte, 0, len(a)+len(b))
	e = append(e, a...)
	e = append(e, b...)

	return e
}

// concat returns the concatenation of the two input byte strings.
func concat(a, b []byte) []byte {
	e := make([]byte, 0, len(a)+len(b))
	e = append(e, a...)
	e = append(e, b...)

	return e
}

// concat3 returns the concatenation of the three input byte strings.
func concat3(a, b, c []byte) []byte {
	e := make([]byte, 0, len(a)+len(b)+len(c))
	e = append(e, a...)
	e = append(e, b...)
	e = append(e, c...)

	return e
}

// TODO: empty password -> for the issue
// TODO: weak password -> new issue, offline check
func (s *Server) EnvelopeCheck(record *RegistrationRecord, c *Client, credentialIdentifier, oprfSeed []byte, serverPublicKey []byte, serverIdentity []byte, clientIdentity []byte) bool {
	env := &keyrecovery.Envelope{}
	envelope, err := env.DeserializeEnvelope(record.Envelope)
	if err != nil {
		return false
	}

	// Fake first client message
	m1 := c.OPRF.Blind([]byte(""), nil) // random blind

	// Calculate the per-client server key
	// TODO: we might be able to run for all clients
	r := hkdf.Expand(
		sha512.New,
		oprfSeed,
		suffixString(credentialIdentifier, tag.ExpandOPRF),
	)
	seedSk := make([]byte, seedLength)
	if _, err := io.ReadFull(r, seedSk); err != nil {
		log.Fatalf("hkdf expand failed: %v", err)
	}

	ku := oprf.DeriveKey(seedSk, []byte(tag.DeriveKeyPair))
	m2 := oprf.Evaluate(ku, m1)

	// Fake last client message
	m3 := c.OPRF.Finalize(m2)

	stretched := ksf.Argon2id.Harden(m3, nil, c.conf.Group.ElementLength()) // if random-salt, it will be though
	prk := hkdf.Extract(sha512.New, concat(m3, stretched), []byte(""))

	r1 := hkdf.Expand(
		sha512.New,
		prk,
		suffixString(envelope.Nonce, tag.ExpandPrivateKey),
	)
	seed := make([]byte, seedLength)
	if _, err := io.ReadFull(r1, seed); err != nil {
		log.Fatalf("hkdf expand failed: %v", err)
	}

	_, pku := oprf.DeriveKeyPair(seed, []byte(tag.DeriveDiffieHellmanKeyPair))
	if clientIdentity == nil {
		clientIdentity = pku.Encode()
	}

	if serverIdentity == nil {
		serverIdentity = serverPublicKey
	}

	ctc := concat3(
		serverPublicKey,
		encoding.EncodeVector(clientIdentity),
		encoding.EncodeVector(serverIdentity),
	)

	r2 := hkdf.Expand(
		sha512.New,
		prk,
		suffixString(envelope.Nonce, tag.AuthKey),
	)
	authKey := make([]byte, c.conf.KDF.Size())
	if _, err := io.ReadFull(r2, authKey); err != nil {
		log.Fatalf("hkdf expand failed: %v", err)
	}

	hm := hmac.New(sha512.New, authKey)
	_, _ = hm.Write(concat(envelope.Nonce, ctc))
	authTag := hm.Sum(nil)

	// TODO: needs constant time
	if bytes.Equal(envelope.AuthTag, authTag) {
		return true
	}

	return false
}
