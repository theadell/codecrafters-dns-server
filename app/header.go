package main

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Header represents the header section of a DNS message.
//
// # RFC 1035 - Section 4.1.1
//
// ```
//
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                      ID                       |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                    QDCOUNT                    |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                    ANCOUNT                    |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                    NSCOUNT                    |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                    ARCOUNT                    |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// ```
type Header struct {
	// ID is the packet identifier, used for matching responses with queries (16 bits).
	ID uint16
	// QR is the Query/Response flag; false for query (0), true for response (1) (1 bit).
	QR bool
	// OPCODE is the operation code, indicating the kind of query (4 bits).
	// Typically 0 for standard queries, with other values defined in RFC 1035 and subsequent RFCs.
	OPCODE uint8
	// AA is the Authoritative Answer flag, indicating if the server is an authority for the domain name in question (1 bit).
	AA bool
	// TC is the Truncation flag, indicating that this message was truncated (1 bit).
	TC bool
	// RD is the Recursion Desired flag, directing the name server to pursue the query recursively (1 bit).
	RD bool
	// RA is the Recursion Available flag, denoting recursive query support in the name server (1 bit).
	RA bool
	// Z is a reserved field, currently unused and must be zero (3 bits).
	Z uint8
	// RCode is the Response Code, indicating the status of the response (4 bits).
	RCode uint8
	// QDCount is the number of entries in the question section (16 bits).
	QDCount uint16
	// ANCount is the number of resource records in the answer section (16 bits).
	ANCount uint16
	// NSCount is the number of name server resource records in the authority section (16 bits).
	NSCount uint16
	// ARCount is the number of resource records in the additional records section (16 bits).
	ARCount uint16
}

// Pack converts the Header struct into a byte slice representation suitable for DNS message transmission.
func (h *Header) Pack() []byte {

	const headerSize = 12
	buf := bytes.NewBuffer(make([]byte, 0, headerSize))

	writeUint16 := func(value uint16) {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, value)
		buf.Write(b)
	}

	// Write packet Id
	writeUint16(h.ID)

	// Write flags
	flags := uint16(0)
	if h.QR {
		flags |= 1 << 15
	}
	// OPCODE
	flags |= uint16(h.OPCODE&0x0F) << 11
	if h.AA {
		flags |= 1 << 10
	}
	if h.TC {
		flags |= 1 << 9
	}
	if h.RD {
		flags |= 1 << 8
	}
	if h.RA {
		flags |= 1 << 7
	}
	// Z is always zero (3 bits), no action needed
	rcode := h.RCode & 0x0F
	flags |= uint16(rcode)
	writeUint16(flags)
	// Write Counts
	writeUint16(h.QDCount)
	writeUint16(h.ANCount)
	writeUint16(h.NSCount)
	writeUint16(h.ARCount)

	return buf.Bytes()

}

var ErrInvalidHeaderLength = errors.New("header byte slice must be exactly 12 bytes")

// UnpackHeader takes a byte slice and constructs a Header struct from it.
func UnpackHeader(b []byte) (Header, error) {
	if len(b) != 12 {
		return Header{}, ErrInvalidHeaderLength
	}
	var h Header
	// 2 byte packet ID
	h.ID = binary.BigEndian.Uint16(b[:2])
	// 2 byte Flags
	flags := binary.BigEndian.Uint16(b[2:4])
	h.QR = (flags>>15)&1 == 1
	h.OPCODE = uint8((flags >> 11) & 0x0F) // 4 bit OPCODE (bits 14 to 11)
	h.AA = (flags>>10)&1 == 1
	h.TC = (flags>>9)&1 == 1
	h.RD = (flags>>8)&1 == 1
	h.RA = (flags>>7)&1 == 1
	h.Z = 0 // Z field (bits 4-6) is reserved and should be zero
	h.RCode = uint8(flags & 0x0F)
	// Section counts
	h.QDCount = binary.BigEndian.Uint16(b[4:6])
	h.ANCount = binary.BigEndian.Uint16(b[6:8])
	h.NSCount = binary.BigEndian.Uint16(b[8:10])
	h.ARCount = binary.BigEndian.Uint16(b[10:12])

	return h, nil
}
