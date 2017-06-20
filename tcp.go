package main

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/juju/ratelimit"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// Create a SOCKS server listening on addr and proxy to server.
func socksLocal(addr, server string, shadow func(net.Conn) net.Conn) {
	logf("SOCKS proxy %s <-> %s", addr, server)
	tcpLocal(addr, server, shadow, func(c net.Conn) (socks.Addr, error) { return socks.Handshake(c) })
}

// Create a TCP tunnel from addr to target via server.
func tcpTun(addr, server, target string, shadow func(net.Conn) net.Conn) {
	tgt := socks.ParseAddr(target)
	if tgt == nil {
		logf("invalid target address %q", target)
		return
	}
	logf("TCP tunnel %s <-> %s <-> %s", addr, server, target)
	tcpLocal(addr, server, shadow, func(net.Conn) (socks.Addr, error) { return tgt, nil })
}

// Listen on addr and proxy to server to reach target from getAddr.
func tcpLocal(addr, server string, shadow func(net.Conn) net.Conn, getAddr func(net.Conn) (socks.Addr, error)) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return
	}

	for {
		c, err := l.Accept()
		if err != nil {
			logf("failed to accept: %s", err)
			continue
		}

		go func() {
			defer c.Close()
			c.(*net.TCPConn).SetKeepAlive(true)

			tgt, err := getAddr(c)
			if err != nil {
				logf("failed to get target address: %v", err)
				return
			}

			rc, err := net.Dial("tcp", server)
			if err != nil {
				logf("failed to connect to server %v: %v", server, err)
				return
			}
			defer rc.Close()
			rc.(*net.TCPConn).SetKeepAlive(true)
			rc = shadow(rc)

			if _, err = rc.Write(tgt); err != nil {
				logf("failed to send target address: %v", err)
				return
			}

			logf("proxy %s <-> %s <-> %s", c.RemoteAddr(), server, tgt)
			_, _, err = relay(nil, rc, c)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return // ignore i/o timeout
				}
				logf("relay error: %v", err)
			}
		}()
	}
}

// Listen on addr for incoming connections.
func tcpRemote(ctx *context.Context, addr string, shadow func(net.Conn) net.Conn) {
	manager := (*ctx).Value("manager").(*Manager)

	l, err := net.Listen("tcp", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return
	}
	defer l.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	manager.AddTCPRelay(port, l)

	logf("listening TCP on %s", addr)
	for {
		c, err := l.Accept()
		if err != nil {
			logf("failed to accept, exit: %v", err)

			// TODO we should we continue here, and make a mechanism
			// for detecting socket close, properly and gracefully
			// shutdown other active connections.
			break
		}

		go func() {
			defer c.Close()
			c.(*net.TCPConn).SetKeepAlive(true)
			c = shadow(c)

			tgt, err := socks.ReadAddr(c)
			if err != nil {
				logf("failed to get target address: %v", err)
				return
			}

			if manager.IsBlock(tgt.String()) {
				logf("block %s <-> %s <-> %s", c.RemoteAddr(), c.LocalAddr(), tgt)
				return
			}

			rc, err := net.Dial("tcp", tgt.String())
			if err != nil {
				logf("failed to connect to target: %v", err)
				return
			}
			defer rc.Close()
			rc.(*net.TCPConn).SetKeepAlive(true)

			un, dn, err := relay(ctx, c, rc)
			logf("proxy %s <-> %s <-> %s %d", c.RemoteAddr(), c.LocalAddr(), tgt, int(un+dn))

			// traffic statistics would be calculated after the relay has been done,
			// we shall wrap the io.Reader and io.Writer just like what ratelimit
			// package do to make the statistics more smoothly.
			manager.UpdateStats(port, int(un+dn))

			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return // ignore i/o timeout
				}
				logf("relay error: %v", err)
			}
		}()
	}
}

// relay copies between left and right bidirectionally. Returns number of
// bytes copied from right to left, from left to right, and any error occurred.
func relay(ctx *context.Context, left, right net.Conn) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	var manager *Manager
	var leftPort string
	var leftReader io.Reader
	var leftWriter io.Writer
	if ctx != nil {
		manager = (*ctx).Value("manager").(*Manager)
		_, leftPort, _ = net.SplitHostPort(left.LocalAddr().String())
		// left read is the client upload process
		leftReader = ratelimit.Reader(left, manager.GetUploadLimitBucket(leftPort))
		// left write is the client download process
		leftWriter = ratelimit.Writer(left, manager.GetDownloadLimitBucket(leftPort))
	}

	go func() {
		var n int64
		var err error
		if ctx != nil {
			n, err = io.Copy(right, leftReader)
		} else {
			n, err = io.Copy(right, left)
		}
		right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
		left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
		ch <- res{n, err}
	}()

	var n int64
	var err error
	if ctx != nil {
		n, err = io.Copy(leftWriter, right)
	} else {
		n, err = io.Copy(left, right)
	}
	right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
	left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	return n, rs.N, err
}
