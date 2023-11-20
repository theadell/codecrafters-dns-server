package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

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

func (h *Header) marshalBinary() []byte {
	buf := bytes.Buffer{}
	b := make([]byte, 2)
	// write packet id
	binary.BigEndian.PutUint16(b, h.ID)
	buf.Write(b)
	// QR, OPCODE, AA, TC and RD ... RCode
	bits := uint16(0)
	if h.QR {
		bits |= 1 << 15
	}
	opcode := h.OPCODE & 0x0F // Mask with 0x0F to keep only the lower 4 bits
	// shift by 11 bits so that the MSB of opcode is at the 14th bit of `bits`
	bits |= uint16(opcode) << 11

	if h.AA {
		bits |= 1 << 10
	}
	if h.TC {
		bits |= 1 << 9
	}
	if h.RD {
		bits |= 1 << 8
	}
	if h.RA {
		bits |= 1 << 7
	}
	// Z is always zero (3bits) > do nothing
	rcode := h.RCode & 0x0F
	// RCode occupies the least significant 4 bits.
	bits |= uint16(rcode)
	binary.BigEndian.PutUint16(b, bits)
	buf.Write(b)
	binary.BigEndian.PutUint16(b, h.QDCount)
	buf.Write(b)
	binary.BigEndian.PutUint16(b, h.ANCount)
	buf.Write(b)
	binary.BigEndian.PutUint16(b, h.NSCount)
	buf.Write(b)
	binary.BigEndian.PutUint16(b, h.ARCount)
	buf.Write(b)
	return buf.Bytes()
}
func (h *Header) unmarshalBinary(data []byte) {
	h.ID = binary.BigEndian.Uint16(data[:2])
	bits := binary.BigEndian.Uint16(data[2:4])
	h.QR = (bits>>15)&1 == 1
	h.OPCODE = uint8((bits >> 11) & 0x0F)
	h.AA = (bits>>10)&1 == 1
	h.TC = (bits>>9)&1 == 1
	h.RD = (bits>>8)&1 == 1
	h.RA = (bits>>7)&1 == 1
	h.Z = 0
	h.RCode = uint8(bits & 0x0F)
	h.QDCount = binary.BigEndian.Uint16(data[4:6])
	h.ANCount = binary.BigEndian.Uint16(data[6:8])
	h.NSCount = binary.BigEndian.Uint16(data[8:10])
	h.ARCount = binary.BigEndian.Uint16(data[10:12])
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

func (q *Question) marshalBinary() []byte {
	buf := new(bytes.Buffer)
	encodeLabels(q.Name, buf)
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, q.Type)
	buf.Write(b)
	binary.BigEndian.PutUint16(b, q.Class)
	buf.Write(b)
	return buf.Bytes()
}
func encodeLabels(name string, buf *bytes.Buffer) {
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) > 0 {
			buf.WriteByte(byte(len(label)))
			buf.WriteString(label)
		}
	}
	buf.WriteByte(0)
}

// Answer represents a DNS Resource Record (RR) as defined in the DNS protocol.
// Each Answer contains the data about the domain name and the resource record associated with it.
type Answer struct {
	// Name represents the domain name encoded as a sequence of labels.
	// Each label is a length-prefixed string, and the sequence is terminated by a zero-length label.
	Name string

	// Type is a 2-byte integer indicating the type of the record.
	// Common values are 1 for an A record, 5 for a CNAME record, etc.
	// The full list of types is specified in the DNS protocol specification.
	Type uint16

	// Class is a 2-byte integer typically set to 1 for Internet (IN) class.
	// Other values are less common and are detailed in the DNS protocol specification.
	Class uint16

	// TTL (Time-To-Live) is a 4-byte integer that specifies the duration in seconds
	// that the record may be cached before it should be discarded or refreshed.
	TTL uint32

	// RDLength is a 2-byte integer that specifies the length of the RDATA field in bytes.
	Length uint16

	// Data (RDATA) is a variable-length field containing the data of the record.
	// The format of this data varies depending on the Type and Class of the record.
	Data []byte
}

func (a *Answer) marshalBinary() []byte {
	buf := new(bytes.Buffer)
	encodeLabels(a.Name, buf)
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
	buf.Write(a.Data)
	return buf.Bytes()
}

type DNSMessage struct {
	Header           Header
	QuestionSection  Question
	AnswerSection    Answer
	AuthoritySecrion []byte
}

func parseDNSPacket(packet []byte) (*DNSMessage, error) {

	var header Header
	var question Question
	header.unmarshalBinary(packet[:12])

	payload := bytes.NewBuffer(packet[12:])

	var labels []string
	var length int

	for {
		if lengthByte, err := payload.ReadByte(); err != nil {
			return nil, err
		} else if lengthByte == 0 {
			break
		} else {
			length = int(lengthByte)
			label := make([]byte, length)
			if _, err := payload.Read(label); err != nil {
				return nil, err
			}
			labels = append(labels, string(label))
		}
	}

	question.Name = strings.Join(labels, ".")
	b := make([]byte, 4)
	_, err := payload.Read(b)
	if err != nil {
		return nil, err
	}
	question.Type = binary.BigEndian.Uint16(b[:2])
	question.Class = binary.BigEndian.Uint16(b[2:4])

	return &DNSMessage{
		Header:           header,
		QuestionSection:  question,
		AnswerSection:    Answer{},
		AuthoritySecrion: []byte{},
	}, nil
}

func (m *DNSMessage) marshalBinary() []byte {
	buf := new(bytes.Buffer)
	buf.Write(m.Header.marshalBinary())
	buf.Write(m.QuestionSection.marshalBinary())
	buf.Write(m.AnswerSection.marshalBinary())
	return buf.Bytes()
}

func main() {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		recvMsg, err := parseDNSPacket(buf[:size])
		if err != nil {
			fmt.Println("Failed to parse packet", err)
		}
		var response DNSMessage
		response.Header.ID = recvMsg.Header.ID
		response.Header.OPCODE = recvMsg.Header.OPCODE
		if response.Header.OPCODE == 0 {
			response.Header.RCode = 0
		} else {
			response.Header.RCode = 4
		}
		response.Header.RD = recvMsg.Header.RD
		response.Header.QR = true
		response.Header.QDCount = 1
		response.Header.ANCount = 1
		response.QuestionSection = recvMsg.QuestionSection
		answerIp := net.ParseIP("8.8.8.8")
		answerIpData := answerIp.To4()
		a := Answer{
			Name:   recvMsg.QuestionSection.Name,
			Type:   recvMsg.QuestionSection.Type,
			Class:  recvMsg.QuestionSection.Class,
			Length: uint16(len(answerIpData)),
			Data:   answerIpData,
		}
		response.AnswerSection = a
		_, err = udpConn.WriteToUDP(response.marshalBinary(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
