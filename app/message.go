package main

import (
	"bytes"
)

// DNSMessage represents a complete DNS message.
//
// # RFC 1035 - Section 4.1
//
// ```
//
//	+---------------------+
//	|        Header       |
//	+---------------------+
//	|       Question      | the question for the name server
//	+---------------------+
//	|        Answer       | RRs answering the question
//	+---------------------+
//	|      Authority      | RRs pointing toward an authority
//	+---------------------+
//	|      Additional     | RRs holding additional information
//	+---------------------+
//
// ```
type DNSMessage struct {
	Header           Header
	QuestionSection  QuestionSection
	AnswerSection    AnswerSection
	AuthoritySecrion []byte
}

// UnpackDNSMessage parses a DNS message from a given packet (byte slice) received over the network into a DNSMessage struct.
// Returns a pointer to DNSMessage and an error if any part of the message cannot be successfully parsed.
func UnpackDNSMessage(packet []byte) (*DNSMessage, error) {
	msg := &DNSMessage{}
	header, err := UnpackHeader(packet[:12])
	if err != nil {
		return nil, err
	}

	payload := bytes.NewBuffer(packet[12:])
	questions, err := UnpackQuestionSection(payload, packet, int(header.QDCount))
	if err != nil {
		return nil, err
	}
	answers, err := UnpackAnswerSection(payload, packet, int(header.ANCount))
	if err != nil {
		return nil, err
	}
	msg.Header = header
	msg.QuestionSection = questions
	msg.AnswerSection = answers
	return msg, nil
}

func (m *DNSMessage) Pack() []byte {
	buf := new(bytes.Buffer)
	buf.Write(m.Header.Pack())
	for _, q := range m.QuestionSection {
		buf.Write(q.Pack())
	}
	for _, a := range m.AnswerSection {
		buf.Write(a.Pack())
	}
	return buf.Bytes()
}
