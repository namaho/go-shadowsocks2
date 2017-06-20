package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"sync"

	"github.com/shadowsocks/go-shadowsocks2/socks"
)

const udpBufSize = 1460

// Listen on laddr for UDP packets, encrypt and send to server to reach target.
func udpLocal(laddr, server, target string, shadow func(net.PacketConn) net.PacketConn) {
	srvAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		logf("UDP server address error: %v", err)
		return
	}

	tgt := socks.ParseAddr(target)
	if tgt == nil {
		err = fmt.Errorf("invalid target address: %q", target)
		logf("UDP target address error: %v", err)
		return
	}

	c, err := net.ListenPacket("udp", laddr)
	if err != nil {
		logf("UDP local listen error: %v", err)
		return
	}
	defer c.Close()

	nm := newNATmap(config.UDPTimeout)
	buf := make([]byte, udpBufSize)
	copy(buf, tgt)

	logf("UDP tunnel %s <-> %s <-> %s", laddr, server, target)
	for {
		n, raddr, err := c.ReadFrom(buf[len(tgt):])
		if err != nil {
			logf("UDP local read error: %v", err)
			continue
		}

		pc := nm.Get(raddr.String())
		if pc == nil {
			pc, err = net.ListenPacket("udp", "")
			if err != nil {
				logf("UDP local listen error: %v", err)
				continue
			}

			pc = shadow(pc)
			nm.Add(nil, raddr, c, pc, false)
		}

		_, err = pc.WriteTo(buf[:len(tgt)+n], srvAddr)
		if err != nil {
			logf("UDP local write error: %v", err)
			continue
		}
	}
}

// Listen on addr for encrypted packets and basically do UDP NAT.
func udpRemote(ctx *context.Context, addr string, shadow func(net.PacketConn) net.PacketConn) {
	manager := (*ctx).Value("manager").(*Manager)

	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		logf("UDP remote listen error: %v", err)
		return
	}
	defer c.Close()
	_, port, _ := net.SplitHostPort(c.LocalAddr().String())
	manager.AddUDPRelay(port, c)
	c = shadow(c)

	nm := newNATmap(config.UDPTimeout)

	logf("listening UDP on %s", addr)
	for {
		buf := make([]byte, udpBufSize)
		n, raddr, err := c.ReadFrom(buf)
		if err != nil {
			logf("UDP remote read error, exit: %v", err)

			// TODO we should we continue here, and make a mechanism
			// for detecting socket close, properly and gracefully
			// shutdown other active connections.
			break
		}

		tgtAddr := socks.SplitAddr(buf[:n])
		if tgtAddr == nil {
			logf("failed to split target address from packet: %q", buf[:n])
			continue
		}

		if manager.IsBlock(tgtAddr.String()) {
			// udp traffic is negligible compared to tcp, and they log too much, we don't acutally need them
			// logf("block udp %s -> %s -> %s", raddr.String(), c.LocalAddr().String(), tgtAddr.String())
			continue
		}

		tgtUDPAddr, err := net.ResolveUDPAddr("udp", tgtAddr.String())
		if err != nil {
			logf("failed to resolve target UDP address: %v", err)
			continue
		}

		payload := buf[len(tgtAddr):n]

		pc := nm.Get(raddr.String())
		if pc == nil {
			pc, err = net.ListenPacket("udp", "")
			if err != nil {
				logf("UDP remote listen error: %v", err)
				continue
			}

			// logf("add remote udp conn to natmap(%d) %s:net.PacketConn(%s)", nm.GetSize(), raddr.String(), pc.LocalAddr().String())
			nm.Add(ctx, raddr, c, pc, true)
		}

		n, err = pc.WriteTo(payload, tgtUDPAddr) // accept only UDPAddr despite the signature
		if err != nil {
			logf("UDP remote write error: %v", err)
			continue
		}
		// udp traffic is negligible compared to tcp, and they log too much, we don't acutally need them
		// logf("udp up %s -> %s -> %s %d", raddr.String(), c.LocalAddr().String(), tgtUDPAddr.String(), n)

		manager.UpdateStats(port, int(n))
	}
}

// Packet NAT table
type natmap struct {
	sync.RWMutex
	m       map[string]net.PacketConn
	timeout time.Duration
}

func newNATmap(timeout time.Duration) *natmap {
	m := &natmap{}
	m.m = make(map[string]net.PacketConn)
	m.timeout = timeout
	return m
}

func (m *natmap) Get(key string) net.PacketConn {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *natmap) Set(key string, pc net.PacketConn) {
	m.Lock()
	defer m.Unlock()

	m.m[key] = pc
}

func (m *natmap) Del(key string) net.PacketConn {
	m.Lock()
	defer m.Unlock()

	pc, ok := m.m[key]
	if ok {
		delete(m.m, key)
		return pc
	}
	return nil
}

func (m *natmap) GetSize() int {
	m.Lock()
	defer m.Unlock()
	return len(m.m)
}

func (m *natmap) Add(ctx *context.Context, peer net.Addr, dst, src net.PacketConn, srcIncluded bool) {
	m.Set(peer.String(), src)

	go func() {
		if err := timedCopy(ctx, dst, peer, src, m.timeout, srcIncluded); err != nil {
			logf("send udp error: %v", err)
		}
		if pc := m.Del(peer.String()); pc != nil {
			pc.Close()
		}
	}()
}

// copy from src to dst at target with read timeout
func timedCopy(ctx *context.Context, dst net.PacketConn, target net.Addr, src net.PacketConn, timeout time.Duration, srcIncluded bool) error {
	buf := make([]byte, udpBufSize)

	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, raddr, err := src.ReadFrom(buf)
		if err != nil {
			return err
		}

		if srcIncluded { // server -> client: add original packet source
			srcAddr := socks.ParseAddr(raddr.String())
			copy(buf[len(srcAddr):], buf[:n])
			copy(buf, srcAddr)
			_, err = dst.WriteTo(buf[:len(srcAddr)+n], target)
		} else { // client -> user: strip original packet source
			srcAddr := socks.SplitAddr(buf[:n])
			_, err = dst.WriteTo(buf[len(srcAddr):n], target)
		}
		// udp traffic is negligible compared to tcp, and they log too much, we don't acutally need them
		// logf("udp dn %s <- %s <- %s %d", target.String(), src.LocalAddr().String(), raddr.String(), n)

		if ctx != nil {
			manager := (*ctx).Value("manager").(*Manager)
			_, port, _ := net.SplitHostPort(dst.LocalAddr().String())
			manager.UpdateStats(port, int(n))
		}

		if err != nil {
			return err
		}
	}
}
