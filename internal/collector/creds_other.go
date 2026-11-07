//go:build !linux

package collector

import (
	"net"
)

// PeerCreds holds process credentials of the connected peer.
type PeerCreds struct {
	PID int32
	UID uint32
	GID uint32
}

// GetPeerCredentials fallback for non-Linux platforms.
func GetPeerCredentials(conn *net.UnixConn) (*PeerCreds, error) {
	return &PeerCreds{PID: 1, UID: 0, GID: 0}, nil
}
