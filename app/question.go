package main

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// Question represents an entry in the Question Section of a DNS message.
//
// # RFC 1035 - Section 4.1.2
// ```
//
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                                               |
//	/                     QNAME                     /
//	/                                               /
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                     QTYPE                     |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|                     QCLASS                    |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// ```
type Question struct {
	// QNAME: Domain name represented as a sequence of labels.
	Name string
	// QTYPE: Two octet code which specifies the type of the query.
	Type uint16
	// QCLASS: A two octet code that specifies the class of the query.
	Class uint16
}

// Pack converts the Question struct into a byte slice representation suitable for DNS message transmission.
//
// Note: Pack doesn't compress QNAME, it just encondes it as a sequence of labels terminated by a zero byte.
func (q *Question) Pack() []byte {
	buf := new(bytes.Buffer)
	packDomainNameToLabelSequence(q.Name, buf)
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, q.Type)
	buf.Write(b)
	binary.BigEndian.PutUint16(b, q.Class)
	buf.Write(b)
	return buf.Bytes()
}
func packDomainNameToLabelSequence(name string, buf *bytes.Buffer) {
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) > 0 {
			buf.WriteByte(byte(len(label)))
			buf.WriteString(label)
		}
	}
	buf.WriteByte(0)
}

// UnpackQuestion parses a DNS question section from a given payload buffer and the entire packet.
//
// The enire packet is needed to handle the case of compressed messages.
// The caller must ensure that the buffer is pointing to the beginning of the question section.
//
// The section contains a domain name, represented either as a sequence of labels (each preceded by its length)
// or a pointer to a prior occurrence of the same name in the packet, or a combination of both. This
// function handles these scenarios to accurately reconstruct the domain name.
//
// In the case of a label, the first byte indicates the length of the label, followed by the label itself.
// A zero-length byte signifies the end of the domain name. In the case of a pointer, the first two bits
// of the first byte are set to '11', and the remaining 14 bits represent an offset from the start of the packet
// to the location of the domain name. This function detects pointers and resolves them to reconstruct
// the complete domain name.
//
// After processing the domain name, the function then reads the next two fields: the question type (QTYPE)
// and question class (QCLASS), each occupying 2 bytes.
//
// DNS Question Format:
//
// ```
//
//	+---------------------+
//	| Label Length (1B)   |  <-- Length of the label (if first two bits are 11, it's a pointer)
//	+---------------------+
//	| Label (Variable)    |  <-- Label itself (if previous byte was a length)
//	+---------------------+
//	| 0x00                |  <-- End of domain name
//	+---------------------+
//	| Type (2B)           |  <-- Type of DNS query (e.g., A, MX, etc.)
//	+---------------------+
//	| Class (2B)          |  <-- Class of DNS query (e.g., IN for Internet)
//	+---------------------+
//	```
//	in case of compression
//	```
//	+---------------------+
//	| 11 (2 bits)         |  <-- Indicator that this is a pointer
//	+---------------------+
//	| Offset (14 bits)    |  <-- Offset to the location of the domain name in the packet
//	+---------------------+
//
// ```
func UnpackQuestion(payload *bytes.Buffer, packet []byte) (Question, error) {
	var question Question

	name, err := unpackDNSName(payload, packet)
	if err != nil {
		return Question{}, err
	}
	question.Name = name
	// Read Type and Class
	err = binary.Read(payload, binary.BigEndian, &question.Type)
	if err != nil {
		return Question{}, err
	}
	err = binary.Read(payload, binary.BigEndian, &question.Class)
	if err != nil {
		return Question{}, err
	}

	return question, nil
}

// unpackDNSName parses a domain name from the DNS payload.
// It handles both regular labels and compressed pointers.
func unpackDNSName(payload *bytes.Buffer, packet []byte) (string, error) {
	var labels []string

	for {
		lengthByte, err := payload.ReadByte()
		if err != nil {
			return "", err
		}

		// 0 byte means the end of a name
		if lengthByte == 0 {
			break
		}

		// if the 2 MSB of this byte are b11, this means it is a pointer
		if lengthByte&0xC0 == 0xC0 {
			secondByte, err := payload.ReadByte()
			if err != nil {
				return "", err
			}
			// offset is the next 14 bits interpted as uinit 16
			// first byte is masked with 0x3F to unset the 2 MSB
			offset := int(lengthByte&0x3F)<<8 + int(secondByte)

			// Extract name from the offset
			offsetPayload := bytes.NewBuffer(packet[offset:])
			for {
				offLengthByte, err := offsetPayload.ReadByte()
				if err != nil {
					return "", err
				}

				if offLengthByte == 0 {
					break
				}

				// Read the label based on its length and append it to labels slice
				offLabel := make([]byte, offLengthByte)
				_, err = offsetPayload.Read(offLabel)
				if err != nil {
					return "", err
				}
				labels = append(labels, string(offLabel))
			}

			// Break out of the main loop as the domain name is fully read
			break
		}

		// Regular label
		label := make([]byte, lengthByte)
		_, err = payload.Read(label)
		if err != nil {
			return "", err
		}
		labels = append(labels, string(label))
	}

	return strings.Join(labels, "."), nil

}

// QuestionSection represents the question section of a dns message
//
// the Question Section of a dns message is a slice of 'Question' where the number of records is specified
// by QDCount in the header
type QuestionSection []Question

// UnpackQuestionSection parses the question section of a DNS message from a byte buffer.
// It processes 'QDCount' resource records from 'payload', using 'packet' for potential name decompression.
// Returns an QuestionSection (slice of Question) and an error if parsing fails for any record.
// the 'payload' buffer must point to the start of the question section
func UnpackQuestionSection(payload *bytes.Buffer, packet []byte, QDCount int) (QuestionSection, error) {
	answerSection := make(QuestionSection, 0, QDCount)
	for i := 0; i < QDCount; i++ {
		q, err := UnpackQuestion(payload, packet)
		if err != nil {
			return nil, err
		}
		answerSection = append(answerSection, q)
	}
	return answerSection, nil
}
