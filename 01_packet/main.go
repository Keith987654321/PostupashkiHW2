package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

func formatMAC(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func formatIP(b []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		word := uint16(header[i])<<8 | uint16(header[i+1])
		sum += uint32(word)

		for sum > 0xffff {
			sum = (sum & 0xffff) + (sum >> 16)
		}
	}

	return ^uint16(sum)
}

func tcpFlags(flags uint8) string {
	var result []string

	if flags&0x01 != 0 {
		result = append(result, "FIN")
	}

	if flags&0x02 != 0 {
		result = append(result, "SYN")
	}

	if flags&0x04 != 0 {
		result = append(result, "RST")
	}

	if flags&0x08 != 0 {
		result = append(result, "PSH")
	}

	if flags&0x10 != 0 {
		result = append(result, "ACK")
	}

	if flags&0x20 != 0 {
		result = append(result, "URG")
	}

	if len(result) == 0 {
		return "none"
	}

	return strings.Join(result, ",")
}

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
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
		panic(err)
	}

	destMAC := packet[0:6]
	sourceMAC := packet[6:12]
	ethertype := binary.BigEndian.Uint16(packet[12:14])

	fmt.Printf("eth.dst %s\n", formatMAC(destMAC))
	fmt.Printf("eth.src %s\n", formatMAC(sourceMAC))
	fmt.Printf("eth.ethertype 0x%04x\n", ethertype)

	if ethertype != 0x0800 {
		return
	}

	ip := packet[14:]
	version := ip[0] >> 4
	ihl := ip[0] & 0x0f
	ihlBytes := int(ihl) * 4
	totalLength := binary.BigEndian.Uint16(ip[2:4])
	ipID := binary.BigEndian.Uint16(ip[4:6])
	flagsOffset := binary.BigEndian.Uint16(ip[6:8])

	df := flagsOffset&(1<<14) != 0
	mf := flagsOffset&(1<<13) != 0
	ipFlags := "none"
	if df && mf {
		ipFlags = "DF,MF"
	} else if df {
		ipFlags = "DF"
	} else if mf {
		ipFlags = "MF"
	}

	fragmentOffset := flagsOffset & 0x1fff
	fragmentOffsetBytes := int(fragmentOffset) * 8

	ttl := ip[8]
	protocol := ip[9]

	originalChecksum := binary.BigEndian.Uint16(ip[10:12])

	soursIP := formatIP(ip[12:16])
	destIP := formatIP(ip[16:20])
	ipHeader := make([]byte, ihlBytes)
	copy(ipHeader, ip[:ihlBytes])
	ipHeader[10] = 0
	ipHeader[11] = 0

	calculatedChecksum := Checksum(ipHeader)
	checksumValid := calculatedChecksum == originalChecksum

	fmt.Printf("ip.version %d\n", version)
	fmt.Printf("ip.ihl_bytes %d\n", ihlBytes)
	fmt.Printf("ip.total_length %d\n", totalLength)
	fmt.Printf("ip.id 0x%04x\n", ipID)
	fmt.Printf("ip.flags %s\n", ipFlags)
	fmt.Printf("ip.frag_offset %d\n", fragmentOffsetBytes)
	fmt.Printf("ip.ttl %d\n", ttl)
	fmt.Printf("ip.protocol %d\n", protocol)
	fmt.Printf("ip.src %s\n", soursIP)
	fmt.Printf("ip.dst %s\n", destIP)
	fmt.Printf("ip.checksum_valid %t\n", checksumValid)

	transport := packet[14+ihlBytes:]
	var payloadLength int

	switch protocol {
	case 6:
		tcp := transport
		sourcePort := binary.BigEndian.Uint16(tcp[0:2])
		destPort := binary.BigEndian.Uint16(tcp[2:4])

		seq := binary.BigEndian.Uint32(tcp[4:8])
		ack := binary.BigEndian.Uint32(tcp[8:12])

		dataOffset := (tcp[12] >> 4) * 4
		flags := tcp[13]

		window := binary.BigEndian.Uint16(tcp[14:16])

		fmt.Printf("tcp.src_port %d\n", sourcePort)
		fmt.Printf("tcp.dst_port %d\n", destPort)
		fmt.Printf("tcp.seq %d\n", seq)
		fmt.Printf("tcp.ack %d\n", ack)
		fmt.Printf("tcp.data_offset_bytes %d\n", dataOffset)
		fmt.Printf("tcp.flags %s\n", tcpFlags(flags))
		fmt.Printf("tcp.window %d\n", window)

		payloadLength = int(totalLength) - ihlBytes - int(dataOffset)
	case 17:
		udp := transport
		srcPort := binary.BigEndian.Uint16(udp[0:2])
		dstPort := binary.BigEndian.Uint16(udp[2:4])
		length := binary.BigEndian.Uint16(udp[4:6])

		fmt.Printf("udp.src_port %d\n", srcPort)
		fmt.Printf("udp.dst_port %d\n", dstPort)
		fmt.Printf("udp.length %d\n", length)
		payloadLength = int(totalLength) - ihlBytes - 8
	default:
		payloadLength = int(totalLength) - ihlBytes
	}

	fmt.Printf("payload.length %d\n", payloadLength)
}
