// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package keyrecovery provides utility functions and structures allowing credential management.
package keyrecovery

import (
	"errors"
	"fmt"

	"github.com/bytemare/ecc"

	"github.com/claucece/opaque-check/internal"
	"github.com/claucece/opaque-check/internal/encoding"
	"github.com/claucece/opaque-check/internal/oprf"
	"github.com/claucece/opaque-check/internal/tag"
)

var errEnvelopeInvalidMac = errors.New("invalid envelope authentication tag")

// Credentials structure is currently used for testing purposes.
type Credentials struct {
	ClientIdentity, ServerIdentity []byte
	EnvelopeNonce                  []byte // testing: integrated to support testing
}

// Envelope represents the OPAQUE envelope.
type Envelope struct {
	Nonce   []byte
	AuthTag []byte
}

// Serialize returns the byte serialization of the envelope.
func (e *Envelope) Serialize() []byte {
	return encoding.Concat(e.Nonce, e.AuthTag)
}

// DeserializeEnvelope parses the byte slice back into an Envelope.
// It assumes the nonce and auth tag are of known fixed lengths.
func (e *Envelope) DeserializeEnvelope(data []byte) (*Envelope, error) {
	if len(data) != internal.NonceLength+internal.MACLength {
		return nil, fmt.Errorf("invalid envelope length")
	}

	env := &Envelope{
		Nonce:   data[:internal.NonceLength],
		AuthTag: data[internal.NonceLength : internal.NonceLength+internal.MACLength],
	}

	return env, nil
}

func authTag(conf *internal.Configuration, randomizedPassword, nonce, ctc []byte) []byte {
	authKey := conf.KDF.Expand(randomizedPassword, encoding.SuffixString(nonce, tag.AuthKey), conf.KDF.Size())
	return conf.MAC.MAC(authKey, encoding.Concat(nonce, ctc))
}

// cleartextCredentials assumes that clientPublicKey, serverPublicKey are non-nil valid group elements.
func cleartextCredentials(clientPublicKey, serverPublicKey, clientIdentity, serverIdentity []byte) []byte {
	if clientIdentity == nil {
		clientIdentity = clientPublicKey
	}

	if serverIdentity == nil {
		serverIdentity = serverPublicKey
	}

	return encoding.Concat3(
		serverPublicKey,
		encoding.EncodeVector(serverIdentity),
		encoding.EncodeVector(clientIdentity),
	)
}

func deriveDiffieHellmanKeyPair(
	conf *internal.Configuration,
	randomizedPassword, nonce []byte,
) (*ecc.Scalar, *ecc.Element) {
	seed := conf.KDF.Expand(randomizedPassword, encoding.SuffixString(nonce, tag.ExpandPrivateKey), internal.SeedLength)
	return oprf.DeriveKeyPair(seed, []byte(tag.DeriveDiffieHellmanKeyPair))
}
