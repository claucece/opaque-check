// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package tag provides the static tag strings to OPAQUE.
package tag

// These strings are the static tags and labels used throughout the protocol.
const (
	// OPRF tags.

	// OPRFVersionPrefix is a string explicitly stating the version name.
	OPRFVersionPrefix = "OPRFV1-\x00-"

	// DeriveKeyPairInternal is the internal DeriveKeyPair tag as defined in VOPRF.
	DeriveKeyPairInternal = "DeriveKeyPair"

	// OPRFPointPrefix is the DST prefix to use for HashToGroup operations.
	OPRFPointPrefix = "HashToGroup-"

	// OPRFFinalize is the DST suffix used in the client transcript.
	OPRFFinalize = "Finalize"

	// Envelope tags.

	// AuthKey is the envelope's MAC key's KDF dst.
	AuthKey = "AuthKey"

	// DeriveDiffieHellmanKeyPair is the private key hash-to-scalar dst.
	DeriveDiffieHellmanKeyPair = "OPAQUE-DeriveDiffieHellmanKeyPair"

	// ExpandPrivateKey is the client's private key seed KDF dst.
	ExpandPrivateKey = "PrivateKey"

	// Server tags.

	// ExpandOPRF is the server's OPRF key seed KDF dst.
	ExpandOPRF = "OprfKey"

	// DeriveKeyPair is the server's OPRF hash-to-scalar dst.
	DeriveKeyPair = "OPAQUE-DeriveKeyPair"
)
