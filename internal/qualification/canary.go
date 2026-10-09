package qualification

import (
	"context"
	"errors"
	"net"
	"time"
)

func receiveUDP(ctx context.Context, conn *net.UDPConn, r *Receipts) {
	buf := make([]byte, 2048)
	for ctx.Err() == nil {
		_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			r.Error = err.Error()
			return
		}
		var packet Packet
		if decode(buf[:n], &packet) != nil || packet.Challenge != r.ChallengeSHA256 || (packet.Role != "job" && packet.Role != "owner") || packet.Attempt < 1 || packet.Attempt > 3 || len(packet.Nonce) != 64 {
			continue
		}
		if len(r.Packets) >= 4096 {
			r.Error = "receipt limit exceeded"
			return
		}
		r.Packets = append(r.Packets, Received{packet, time.Now().UTC(), peer.String()})
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err = conn.WriteToUDP(buf[:n], peer); err != nil {
			r.Error = err.Error()
			return
		}
	}
}
