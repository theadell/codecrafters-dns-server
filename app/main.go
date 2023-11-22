package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
)

func main() {

	resolver := flag.String("resolver", "", "DNS Server Addr to forward to")
	flag.Parse()
	if *resolver == "" {
		println("resolver addr was not set")
		os.Exit(1)
	}
	resolverAddr, err := net.ResolveUDPAddr("udp", strings.TrimSpace(*resolver))
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}
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
		packet := buf[:size]
		recvMsg, err := UnpackDNSMessage(packet)
		if err != nil {
			fmt.Println("Failed to parse packet", err)
		}
		go handleDnsQuery(udpConn, source, recvMsg, resolverAddr)
	}
}

func handleDnsQuery(lconn *net.UDPConn, sourceAddr *net.UDPAddr, msg *DNSMessage, resolverAddr *net.UDPAddr) {
	conn, err := net.DialUDP("udp", nil, resolverAddr)
	if err != nil {
		fmt.Println("failed to create a udp connection", err)
		return
	}
	defer conn.Close()

	answers := make([]ResourceRecord, 0)
	for _, question := range msg.QuestionSection {
		nm := DNSMessage{
			Header:          msg.Header,
			QuestionSection: []Question{question},
			AnswerSection:   []ResourceRecord{},
		}
		nm.Header.QDCount = 1
		nm.Header.ANCount = 0

		nmBytes := nm.Pack()
		_, err = conn.Write(nmBytes)
		if err != nil {
			fmt.Println("failed to write to UDP connection", err)
			continue
		}

		buffer := make([]byte, 512)
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Println("failed to read from UDP connection", err)
			continue
		}

		resp, err := UnpackDNSMessage(buffer[:n])
		if err != nil {
			fmt.Println("failed to unmarshal DNS response", err)
			continue
		}

		answers = append(answers, resp.AnswerSection...)
	}

	finalResponse := DNSMessage{
		Header:          msg.Header,
		QuestionSection: msg.QuestionSection,
		AnswerSection:   answers,
	}
	if finalResponse.Header.OPCODE != 0 {
		finalResponse.Header.RCode = 4
	} else {
		finalResponse.Header.RCode = 0
	}
	finalResponse.Header.QR = true
	finalResponse.Header.ANCount = uint16(len(answers))
	finalResponseBytes := finalResponse.Pack()

	_, err = lconn.WriteToUDP(finalResponseBytes, sourceAddr)
	if err != nil {
		fmt.Println("failed to send response", err)
	}
}
