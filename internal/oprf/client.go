// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package oprf

import (
	"errors"

	"github.com/bytemare/ecc"

	"github.com/claucece/opaque-check/internal/encoding"
	"github.com/claucece/opaque-check/internal/tag"
)

var errInvalidInput = errors.New("invalid input - OPRF input deterministically maps to the group identity element")

// Client implements the OPRF client and holds its state.
type Client struct {
	blind *ecc.Scalar
	input []byte
}

// Blind masks the input.
func (c *Client) Blind(input []byte, blind *ecc.Scalar) *ecc.Element {
	if blind != nil {
		c.blind = blind.Copy()
	} else {
		c.blind = ecc.Ristretto255Sha512.NewScalar().Random()
	}

	p := ecc.Ristretto255Sha512.HashToGroup(input, encoding.Concat([]byte(tag.OPRFPointPrefix), encoding.Concatenate([]byte(tag.OPRFVersionPrefix), []byte("ristretto255-SHA512"))))
	if p.IsIdentity() {
		panic(errInvalidInput)
	}

	c.input = input

	return p.Multiply(c.blind)
}

func hashTranscript(input, unblinded []byte) []byte {
	encInput := encoding.EncodeVector(input)
	encElement := encoding.EncodeVector(unblinded)
	encDST := []byte(tag.OPRFFinalize)

	return hashSha512(encInput, encElement, encDST)
}

// Finalize terminates the OPRF by unblinding the evaluation and hashing the transcript.
func (c *Client) Finalize(evaluation *ecc.Element) []byte {
	invert := c.blind.Copy().Invert()
	u := evaluation.Copy().Multiply(invert).Encode()

	return hashTranscript(c.input, u)
}
