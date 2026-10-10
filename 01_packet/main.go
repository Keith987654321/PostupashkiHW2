package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

func checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		word := uint16(header[i]) << 8

		if i+1 < len(header) {
			word |= uint16(header[i+1])
		}

		sum += uint32(word)
	}

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

func tcpFlags(flags uint8) string {
	allFlags := []struct {
		mask uint8
		name string
	}{
		{0x01, "FIN"},
		{0x02, "SYN"},
		{0x04, "RST"},
		{0x08, "PSH"},
		{0x10, "ACK"},
		{0x20, "URG"},
		{0x40, "ECE"},
		{0x80, "CWR"},
	}

	var result []string

	for _, flag := range allFlags {
		if flags&flag.mask != 0 {
			result = append(result, flag.name)
		}
	}

	if len(result) == 0 {
		return "none"
	}

	return strings.Join(result, ",")
}

func run() error {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t', ':':
			return -1
		default:
			return r
		}
	}, string(input))

	packet, err := hex.DecodeString(clean)
	if err != nil {
		return fmt.Errorf("invalid hex dump: %w", err)
	}

	if len(packet) < 14 {
		return fmt.Errorf("Ethernet frame is too short: %d bytes", len(packet))
	}

	destMAC := net.HardwareAddr(packet[0:6]).String()
	sourceMAC := net.HardwareAddr(packet[6:12]).String()
	ethertype := binary.BigEndian.Uint16(packet[12:14])

	fmt.Printf("eth.dst %s\n", destMAC)
	fmt.Printf("eth.src %s\n", sourceMAC)
	fmt.Printf("eth.ethertype 0x%04x\n", ethertype)

	if ethertype != 0x0800 {
		return nil
	}

	ip := packet[14:]
	if len(ip) < 20 {
		return fmt.Errorf("IPv4 header is too short: %d bytes", len(ip))
	}

	version := ip[0] >> 4
	if version != 4 {
		return fmt.Errorf("unsupported IP version: %d", version)
	}

	ihl := ip[0] & 0x0f
	ihlBytes := int(ihl) * 4

	if ihlBytes < 20 {
		return fmt.Errorf("invalid IPv4 header length: %d bytes", ihlBytes)
	}

	if ihlBytes > len(ip) {
		return fmt.Errorf("IPv4 header exceeds available data")
	}

	totalLength := int(binary.BigEndian.Uint16(ip[2:4]))
	ipID := binary.BigEndian.Uint16(ip[4:6])

	if totalLength < ihlBytes {
		return fmt.Errorf("IPv4 total length is smaller than its header")
	}

	if totalLength > len(ip) {
		return fmt.Errorf(
			"IPv4 total length (%d) exceeds available data (%d)",
			totalLength, len(ip),
		)
	}

	flagsOffset := binary.BigEndian.Uint16(ip[6:8])

	ipFlags := []string{}

	if flagsOffset&(1<<14) != 0 {
		ipFlags = append(ipFlags, "DF")
	}
	if flagsOffset&(1<<13) != 0 {
		ipFlags = append(ipFlags, "MF")
	}

	flagsString := "none"
	if len(ipFlags) > 0 {
		flagsString = strings.Join(ipFlags, ",")
	}

	fragmentOffset := int(flagsOffset&0x1fff) * 8

	ttl := ip[8]
	protocol := ip[9]

	srcIP := net.IP(ip[12:16]).String()
	dstIP := net.IP(ip[16:20]).String()

	checksumValid := checksum(ip[:ihlBytes]) == 0

	fmt.Printf("ip.version %d\n", version)
	fmt.Printf("ip.ihl_bytes %d\n", ihlBytes)
	fmt.Printf("ip.total_length %d\n", totalLength)
	fmt.Printf("ip.id 0x%04x\n", ipID)
	fmt.Printf("ip.flags %s\n", flagsString)
	fmt.Printf("ip.frag_offset %d\n", fragmentOffset)
	fmt.Printf("ip.ttl %d\n", ttl)
	fmt.Printf("ip.protocol %d\n", protocol)
	fmt.Printf("ip.src %s\n", srcIP)
	fmt.Printf("ip.dst %s\n", dstIP)
	fmt.Printf("ip.checksum_valid %t\n", checksumValid)

	transport := ip[ihlBytes:totalLength]

	var payloadLength int

	if fragmentOffset != 0 {
		payloadLength = len(transport)
		fmt.Printf("payload.length %d\n", payloadLength)
		return nil
	}

	switch protocol {
	case 6:
		if len(transport) < 20 {
			return fmt.Errorf("TCP header is too short: %d bytes", len(transport))
		}

		tcp := transport

		sourcePort := binary.BigEndian.Uint16(tcp[0:2])
		destPort := binary.BigEndian.Uint16(tcp[2:4])
		seq := binary.BigEndian.Uint32(tcp[4:8])
		ack := binary.BigEndian.Uint32(tcp[8:12])

		dataOffset := int(tcp[12]>>4) * 4

		if dataOffset < 20 {
			return fmt.Errorf("invalid TCP header length: %d bytes", dataOffset)
		}

		if dataOffset > len(tcp) {
			return fmt.Errorf("TCP header exceeds available data")
		}

		flags := tcp[13]
		window := binary.BigEndian.Uint16(tcp[14:16])

		fmt.Printf("tcp.src_port %d\n", sourcePort)
		fmt.Printf("tcp.dst_port %d\n", destPort)
		fmt.Printf("tcp.seq %d\n", seq)
		fmt.Printf("tcp.ack %d\n", ack)
		fmt.Printf("tcp.data_offset_bytes %d\n", dataOffset)
		fmt.Printf("tcp.flags %s\n", tcpFlags(flags))
		fmt.Printf("tcp.window %d\n", window)

		payloadLength = len(tcp) - dataOffset
	case 17:
		if len(transport) < 8 {
			return fmt.Errorf("UDP header is too short: %d bytes", len(transport))
		}

		udp := transport

		sourcePort := binary.BigEndian.Uint16(udp[0:2])
		destPort := binary.BigEndian.Uint16(udp[2:4])
		udpLength := int(binary.BigEndian.Uint16(udp[4:6]))

		if udpLength < 8 {
			return fmt.Errorf("invalid UDP length: %d bytes", udpLength)
		}

		if !((flagsOffset & (1 << 13)) != 0) && udpLength > len(udp) {
			return fmt.Errorf("UDP length exceeds available IP payload")
		}

		fmt.Printf("udp.src_port %d\n", sourcePort)
		fmt.Printf("udp.dst_port %d\n", destPort)
		fmt.Printf("udp.length %d\n", udpLength)

		payloadLength = len(udp) - 8

	default:
		payloadLength = len(transport)
	}

	fmt.Printf("payload.length %d\n", payloadLength)

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
