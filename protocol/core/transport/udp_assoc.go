// Copyright (C) 2026 Komaru.
// Licensed under the GNU Affero General Public License v3.0.
// See the LICENSE file in the project root for more information.

package transport

import (
	"fmt"
	"log"
	"sync"
)

type UDPAssociation struct {
	id        uint16
	client    *Client
	incoming  chan UDPPayload
	closeOnce sync.Once
}

func (ua *UDPAssociation) Send(addrType byte, addr string, port uint16, data []byte) error {
	if ua == nil || ua.client == nil {
		return fmt.Errorf("udp association unavailable")
	}
	return ua.client.sendUDPFrame(ua.id, addrType, addr, port, data)
}

func (ua *UDPAssociation) Receive() <-chan UDPPayload {
	return ua.incoming
}

func (ua *UDPAssociation) Close() error {
	if ua == nil || ua.client == nil {
		return nil
	}

	ua.closeOnce.Do(func() {
		ua.client.unregisterUDPAssociation(ua.id, true)
	})
	return nil
}

func (c *Client) OpenUDPAssociation() (*UDPAssociation, error) {
	if err := c.EnsurePersistentChannel(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.nextUDPAssocID++
	if c.nextUDPAssocID == 0 {
		c.nextUDPAssocID++
	}
	assocID := c.nextUDPAssocID
	incoming := make(chan UDPPayload, 64)
	c.udpHandlers[assocID] = incoming
	shouldStartLoop := !c.frameLoopActive
	if shouldStartLoop {
		c.frameLoopActive = true
	}
	c.mu.Unlock()

	if shouldStartLoop {
		go c.runFrameLoop()
	}

	return &UDPAssociation{
		id:       assocID,
		client:   c,
		incoming: incoming,
	}, nil
}

func (c *Client) sendUDPFrame(assocID uint16, addrType byte, addr string, port uint16, data []byte) error {
	if err := c.EnsurePersistentChannel(); err != nil {
		return err
	}

	c.mu.Lock()
	writer := c.writer
	c.mu.Unlock()
	if writer == nil {
		return fmt.Errorf("persistent channel unavailable")
	}

	if err := writer.WriteTypedFrame(EncodeUDPFrame(assocID, addrType, addr, port, data)); err != nil {
		return err
	}
	return writer.Flush()
}

func (c *Client) unregisterUDPAssociation(assocID uint16, sendClose bool) {
	var ch chan UDPPayload
	var writer *FrameWriter

	c.mu.Lock()
	ch = c.udpHandlers[assocID]
	delete(c.udpHandlers, assocID)
	if sendClose {
		writer = c.writer
	}
	c.mu.Unlock()

	if sendClose && writer != nil {
		if err := writer.WriteTypedFrame(EncodeUDPCloseFrame(assocID)); err == nil {
			_ = writer.Flush()
		}
	}
	if ch != nil {
		close(ch)
	}
}

func (c *Client) runFrameLoop() {
	for {
		c.mu.Lock()
		reader := c.reader
		c.mu.Unlock()
		if reader == nil {
			c.dropPersistentChannel()
			return
		}

		frame, err := reader.ReadTypedFramePooled()
		if err != nil {
			log.Printf("[Client] Persistent frame loop stopped: %v", err)
			c.dropPersistentChannel()
			return
		}

		switch frame.Type {
		case FrameUDP:
			payload, decodeErr := DecodeUDPFrame(frame.Payload)
			if decodeErr == nil {
				payload.Data = append([]byte(nil), payload.Data...)
				c.dispatchUDPFrame(payload)
			}
		case FrameUDPClose:
			assocID, decodeErr := DecodeUDPCloseFrame(frame.Payload)
			if decodeErr == nil {
				c.unregisterUDPAssociation(assocID, false)
			}
		default:
			payload := append([]byte(nil), frame.Payload...)
			c.enqueueFrame(Frame{Type: frame.Type, Payload: payload})
		}

		frame.Release()
	}
}

func (c *Client) dispatchUDPFrame(payload UDPPayload) {
	c.mu.Lock()
	ch := c.udpHandlers[payload.AssocID]
	c.mu.Unlock()
	if ch == nil {
		return
	}

	defer func() {
		if recover() != nil {
			log.Printf("[Client] Dropping UDP payload for closed association %d", payload.AssocID)
		}
	}()

	select {
	case ch <- payload:
	default:
		log.Printf("[Client] Dropping UDP payload for association %d: receiver is saturated", payload.AssocID)
	}
}

func (c *Client) enqueueFrame(frame Frame) {
	c.mu.Lock()
	inbox := c.frameInbox
	c.mu.Unlock()
	if inbox == nil {
		return
	}

	defer func() {
		if recover() != nil {
			log.Printf("[Client] Dropping frame type %d for closed inbox", frame.Type)
		}
	}()

	select {
	case inbox <- frame:
	default:
		log.Printf("[Client] Dropping frame type %d: inbox is saturated", frame.Type)
	}
}
