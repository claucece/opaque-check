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

	"github.com/bytemare/ecc"
	"github.com/claucece/opaque-check/internal"
	"github.com/claucece/opaque-check/internal/encoding"
	"github.com/claucece/opaque-check/internal/keyrecovery"
	"github.com/claucece/opaque-check/internal/oprf"
	"github.com/claucece/opaque-check/internal/tag"
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
	envelope, err := env.DeserializeEnvelope(record.Envelope, c.conf)
	if err != nil {
		return false
	}

	// Fake first client message
	m1 := c.OPRF.Blind([]byte(""), nil) // random blind

	// Calculate the per-client server key
	// TODO: we might be able to run for all clients
	seedSk := s.conf.KDF.Expand(
		oprfSeed,
		suffixString(credentialIdentifier, tag.ExpandOPRF),
		seedLength,
	)
	ku := s.conf.OPRF.DeriveKey(seedSk, []byte(tag.DeriveKeyPair))
	m2 := s.conf.OPRF.Evaluate(ku, m1)

	// Fake last client message
	m3 := c.OPRF.Finalize(m2)

	stretched := c.conf.KSF.Harden(m3, nil, c.conf.Group.ElementLength()) // if random-salt, it will be though
	prk := c.conf.KDF.Extract([]byte(""), concat(m3, stretched))
	seed := c.conf.KDF.Expand(prk, suffixString(envelope.Nonce, tag.ExpandPrivateKey), seedLength)
	_, pku := oprf.IDFromGroup(c.conf.Group).DeriveKeyPair(seed, []byte(tag.DeriveDiffieHellmanKeyPair))
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
	authKey := c.conf.KDF.Expand(prk, suffixString(envelope.Nonce, tag.AuthKey), c.conf.KDF.Size())
	authTag := c.conf.MAC.MAC(authKey, concat(envelope.Nonce, ctc)) // build the credentials

	// TODO: needs constant time
	if bytes.Equal(envelope.AuthTag, authTag) {
		return true
	}

	return false
}
