// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package viewer

import (
	"crypto/x509"
	"errors"
	"io/fs"
)

// Root is an option that sets the root filesystem for the viewer.  This is
// the root directory that will be used to read files from.  (Required)
func Root(root fs.FS) Option {
	return optionFunc(func(h *Handler) error {
		h.root = root
		return nil
	})
}

// Trust is an option that adds a certificate to the list of trusted roots.
// This is used to verify the certificate of the client.  (Required)
func Trust(certs ...*x509.Certificate) Option {
	return optionFunc(func(h *Handler) error {
		h.trustedRoots = append(h.trustedRoots, certs...)
		return nil
	})
}

// Policies is an option that adds a list of policies for the handler to check
// the certificate chain for. (Optional)
func Policies(policies ...string) Option {
	return optionFunc(func(h *Handler) error {
		h.policies = append(h.policies, policies...)
		return nil
	})
}

//------------------------------------------------------------------------------

func validate() Option {
	return optionFunc(func(h *Handler) error {
		if h.root == nil {
			return errors.New("root is required")
		}

		if len(h.trustedRoots) == 0 {
			return errors.New("trusted roots are required")
		}

		return nil
	})
}
