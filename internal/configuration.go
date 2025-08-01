// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal provides values, structures, and functions to operate OPAQUE that are not part of the public API.
package internal

import (
	"errors"

	"github.com/bytemare/ecc"

	"github.com/claucece/opaque-check/internal/oprf"
)

const (
	// NonceLength is the default length used for nonces.
	NonceLength = 32

	// MACLength is the length used for macs.
	MACLength = 64

	// SeedLength is the default length used for seeds.
	SeedLength = oprf.SeedLength
)

// ErrConfigurationInvalidLength happens when deserializing a configuration of invalid length.
var ErrConfigurationInvalidLength = errors.New("invalid encoded configuration length")

// Configuration is the internal representation of the instance runtime parameters.
type Configuration struct {
	KDF          *KDF
	MAC          *Mac
	Hash         *Hash
	KSF          *KSF
	OPRF         oprf.Identifier
	Context      []byte
	NonceLen     int
	EnvelopeSize int
	Group        ecc.Group
}
