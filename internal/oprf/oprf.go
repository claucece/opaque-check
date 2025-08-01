// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package oprf implements the Elliptic Curve Oblivious Pseudorandom Function (EC-OPRF) from
// https://tools.ietf.org/html/draft-irtf-cfrg-voprf.
package oprf

import (
	"crypto/sha512"

	"github.com/bytemare/ecc"

	"github.com/claucece/opaque-check/internal/encoding"
	"github.com/claucece/opaque-check/internal/tag"
)

// SeedLength is the default length used for seeds.
const SeedLength = 32

// Identifier of the OPRF compatible cipher suite to be used.
type Identifier string

const (
	maxDeriveKeyPairTries = 255
)

func contextString() []byte {
	return encoding.Concatenate([]byte(tag.OPRFVersionPrefix), []byte("ristretto255-SHA512"))
}

func hashSha512(input ...[]byte) []byte {
	h := sha512.New()

	for _, i := range input {
		_, _ = h.Write(i)
	}

	return h.Sum(nil)
}

// DeriveKey returns a scalar deterministically generated from the input.
func DeriveKey(seed, info []byte) *ecc.Scalar {
	dst := encoding.Concat([]byte(tag.DeriveKeyPairInternal), contextString())
	deriveInput := encoding.Concat(seed, encoding.EncodeVector(info))

	var (
		counter uint8
		s       *ecc.Scalar
	)

	for s == nil || s.IsZero() {
		if counter > maxDeriveKeyPairTries {
			panic("DeriveKeyPairError")
		}

		s = ecc.Ristretto255Sha512.HashToScalar(encoding.Concat(deriveInput, []byte{counter}), dst)
		counter++
	}

	return s
}

// DeriveKeyPair returns a valid keypair deterministically generated from the input.
func DeriveKeyPair(seed, info []byte) (*ecc.Scalar, *ecc.Element) {
	sk := DeriveKey(seed, info)
	return sk, ecc.Ristretto255Sha512.Base().Multiply(sk)
}
