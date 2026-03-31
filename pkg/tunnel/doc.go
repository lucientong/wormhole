// Package tunnel provides the core tunneling functionality for Wormhole.
//
// The tunnel package implements a multiplexed connection protocol that allows
// multiple virtual streams to be established over a single TCP connection.
// This is similar to the yamux protocol but with a custom binary frame format.
//
// # Frame Protocol
//
// The frame protocol uses a simple binary format:
//
//	+----------+----------+------------+----------+------------------+
//	| Version  |   Type   |  StreamID  |  Length  |     Payload      |
//	|  1 byte  |  1 byte  |  4 bytes   |  4 bytes |    N bytes       |
//	+----------+----------+------------+----------+------------------+
//
// Frame types:
//   - DATA (0x01): Regular data frame
//   - WINDOW_UPDATE (0x02): Flow control window update
//   - PING (0x03): Keep-alive ping
//   - CLOSE (0x04): Stream close notification
//   - HANDSHAKE (0x05): Initial handshake frame
//   - ERROR (0x06): Error notification
//
// # Usage
//
// Server side:
//
//	mux, err := tunnel.Server(conn, config)
//	if err != nil {
//	    return err
//	}
//	for {
//	    stream, err := mux.AcceptStream()
//	    if err != nil {
//	        return err
//	    }
//	    go handleStream(stream)
//	}
//
// Client side:
//
//	mux, err := tunnel.Client(conn, config)
//	if err != nil {
//	    return err
//	}
//	stream, err := mux.OpenStream(ctx)
//	if err != nil {
//	    return err
//	}
//	// Use stream as io.ReadWriteCloser
package tunnel
