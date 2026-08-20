// Package ui exposes immutable, generated Web assets to the transport layer.
// React and TypeScript remain build-time concerns and cannot import Go code.
package ui

// Bundle identifies a versioned UI asset bundle without loading it eagerly.
type Bundle struct {
	Digest string
}
