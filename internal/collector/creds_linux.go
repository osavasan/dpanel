//go:build linux

package collector

import (
	"fmt"
	"net"
	"syscall"
)

// PeerCreds holds process credentials of the connected peer.
type PeerCreds struct {
	PID int32
	UID uint32
	GID uint32
}

// GetPeerCredentials extracts SO_PEERCRED from a Unix domain socket connection on Linux.
func GetPeerCredentials(conn *net.UnixConn) (*PeerCreds, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil connection")
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed getting raw conn: %w", err)
	}
	var ucred *syscall.Ucred
	var sysErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		ucred, sysErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if ctrlErr != nil {
		return nil, fmt.Errorf("control error: %w", ctrlErr)
	}
	if sysErr != nil {
		return nil, fmt.Errorf("getsockopt peercred error: %w", sysErr)
	}
	return &PeerCreds{
		PID: ucred.Pid,
		UID: ucred.Uid,
		GID: ucred.Gid,
	}, nil
}
