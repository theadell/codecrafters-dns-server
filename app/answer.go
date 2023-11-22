package main

import (
	"bytes"
	"encoding/binary"
)

// ResourceRecord represents a DNS Resource Record (RR) as defined in the DNS protocol.
// Each ResourceRecord contains the data about the domain name and the resource record associated with it.
//
// # RFC 1035 - Section 4.1.3
// ```
//
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                                               |
//	/                                               /
//	/                      NAME                     /
//	|                                               |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                      TYPE                     |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                     CLASS                     |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                      TTL                      |
//	|                                               |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                   RDLENGTH                    |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//	/                     RDATA                     /
//	/                                               /
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// ```
type ResourceRecord struct {
	// Domain name to which this resource record pertains
	Name string

	// RR type code which specifies the meaning of the data in the RDATA field.
	Type uint16

	// Class of the data in the RDATA field.
	Class uint16

	// The time interval (in seconds) that the resource record may be  cached before it should be discarded.
	TTL uint32

	// RDLength is a 2-byte integer that specifies the length of the RDATA field in bytes.
	Length uint16

	// RData is a variable-length field containing the data of the record.
	// The format of this data varies depending on the Type and Class of the record.
	RData []byte
}

// AnswerSection represents the answer section of a dns message
//
// the AnswerSection of a dns message is a slice of resource records where the number of records is specified
// by ANCOUNT in the header
type AnswerSection []ResourceRecord

// Pack converts the RR into a byte slice representation suitable for DNS message transmission.
//
// Note: Pack doesn't compress NAME, it just encondes it as a sequence of labels terminated by a zero byte.
func (a *ResourceRecord) Pack() []byte {
	buf := new(bytes.Buffer)
	packDomainNameToLabelSequence(a.Name, buf)
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, a.Type)
	buf.Write(b)
	binary.BigEndian.PutUint16(b, a.Class)
	buf.Write(b)
	b32 := make([]byte, 4)
	binary.BigEndian.PutUint32(b32, a.TTL)
	buf.Write(b32)
	binary.BigEndian.PutUint16(b, a.Length)
	buf.Write(b)
	buf.Write(a.RData)
	return buf.Bytes()
}

// UnpackRR parses a single Resource Record (RR) from a DNS message.
//
// This function extracts and constructs a ResourceRecord struct from a given byte buffer (payload).
// The payload buffer is expected to contain the RR data starting from the QNAME section. It also uses
// the entire packet byte slice for handling potential name compression in the QNAME field.
func UnpackRR(payload *bytes.Buffer, packet []byte) (ResourceRecord, error) {
	var rr ResourceRecord

	name, err := unpackDNSName(payload, packet)
	if err != nil {
		return ResourceRecord{}, nil
	}
	rr.Name = name
	err = binary.Read(payload, binary.BigEndian, &rr.Type)
	if err != nil {
		return ResourceRecord{}, err
	}
	err = binary.Read(payload, binary.BigEndian, &rr.Class)
	if err != nil {
		return ResourceRecord{}, err
	}
	err = binary.Read(payload, binary.BigEndian, &rr.TTL)
	if err != nil {
		return ResourceRecord{}, err
	}
	err = binary.Read(payload, binary.BigEndian, &rr.Length)
	if err != nil {
		return ResourceRecord{}, err
	}
	dataBuf := make([]byte, rr.Length)
	_, err = payload.Read(dataBuf)
	if err != nil {
		return ResourceRecord{}, err
	}
	rr.RData = dataBuf

	return rr, nil
}

// UnpackAnswerSection parses the answer section of a DNS message from a byte buffer.
// It processes 'ANCount' resource records from 'payload', using 'packet' for potential name decompression.
// Returns an AnswerSection (slice of ResourceRecord) and an error if parsing fails for any record.
// the 'payload' buffer must point to the start of the answer section
func UnpackAnswerSection(payload *bytes.Buffer, packet []byte, ANCount int) (AnswerSection, error) {
	answerSection := make(AnswerSection, 0, ANCount)
	for i := 0; i < ANCount; i++ {
		rr, err := UnpackRR(payload, packet)
		if err != nil {
			return nil, err
		}
		answerSection = append(answerSection, rr)
	}
	return answerSection, nil
}
