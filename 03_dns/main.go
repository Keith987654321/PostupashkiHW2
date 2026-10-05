package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28

	ClassIN uint16 = 1

	readTimeout = 5 * time.Second
)

var errTimeout = errors.New("timeout")

type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type DNSRecord struct {
	Name        string
	Type        uint16
	Class       uint16
	TTL         uint32
	Data        []byte
	RDataOffset int
}

type cacheEntry struct {
	answers []string
	expires time.Time
}

func encodeName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}
	}

	result := make([]byte, 0, len(name)+2)

	for _, part := range strings.Split(name, ".") {
		if len(part) > 63 {
			return nil
		}

		result = append(result, byte(len(part)))
		result = append(result, part...)
	}

	result = append(result, 0)

	return result
}

func encodeHeader(id uint16) []byte {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], 1<<8)
	binary.BigEndian.PutUint16(header[4:6], 1)

	return header
}

func encodeQuestion(name string, questionType uint16) []byte {
	question := encodeName(name)
	if question == nil {
		return nil
	}

	var buf [2]byte
	result := make([]byte, 0, len(question)+4)
	result = append(result, question...)
	binary.BigEndian.PutUint16(buf[:], questionType)
	result = append(result, buf[:]...)
	binary.BigEndian.PutUint16(buf[:], ClassIN)
	result = append(result, buf[:]...)

	return result
}

func buildQuery(id uint16, name string, questionType uint16) ([]byte, error) {
	question := encodeQuestion(name, questionType)
	if question == nil {
		return nil, fmt.Errorf("invalid name")
	}

	header := encodeHeader(id)
	packet := make([]byte, 0, len(header)+len(question))
	packet = append(packet, header...)
	packet = append(packet, question...)

	return packet, nil
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %s", value)
	}

	return port, nil
}

func newQueryID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint16(b[:])
	}

	return uint16(time.Now().UnixNano())
}

func sendQuery(server string, port int, packet []byte, id uint16) ([]byte, error) {
	ip := net.ParseIP(server)
	if ip == nil {
		return nil, fmt.Errorf("invalid address %s", server)
	}

	addr := &net.UDPAddr{
		IP:   ip,
		Port: port,
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return nil, err
	}

	buffer := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return nil, errTimeout
			}

			return nil, err
		}

		if n < 2 {
			continue
		}

		responseID := binary.BigEndian.Uint16(buffer[:2])
		if responseID != id {
			continue
		}

		response := make([]byte, n)
		copy(response, buffer[:n])

		return response, nil
	}
}

func parseHeader(data []byte) (DNSHeader, error) {
	if len(data) < 12 {
		return DNSHeader{}, fmt.Errorf("packet too short")
	}

	return DNSHeader{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   binary.BigEndian.Uint16(data[2:4]),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}, nil
}

func decodeName(
	data []byte,
	offset int,
) (string, int, error) {

	if offset < 0 || offset >= len(data) {
		return "", 0, fmt.Errorf("invalid name offset")
	}

	var labels []string

	pos := offset

	nextOffset := -1

	visited := make(map[int]bool)

	for {
		if pos < 0 || pos >= len(data) {
			return "", 0, fmt.Errorf("name goes beyond packet")
		}

		if visited[pos] {
			return "", 0, fmt.Errorf("compression pointer loop")
		}

		visited[pos] = true

		length := data[pos]

		if length == 0 {
			pos++

			if nextOffset == -1 {
				nextOffset = pos
			}

			return strings.Join(labels, ".") + ".", nextOffset, nil
		}

		if length&0xC0 == 0xC0 {
			if pos+1 >= len(data) {
				return "", 0, fmt.Errorf("incomplete compression pointer")
			}

			pointer := int(
				binary.BigEndian.Uint16(data[pos:pos+2]) & 0x3FFF,
			)

			if nextOffset == -1 {
				nextOffset = pos + 2
			}

			pos = pointer
			continue
		}

		if length&0xC0 != 0 {
			return "", 0, fmt.Errorf("invalid label length")
		}

		pos++

		end := pos + int(length)

		if end > len(data) {
			return "", 0, fmt.Errorf("label goes beyond packet")
		}

		labels = append(labels, string(data[pos:end]))

		pos = end
	}
}

func skipQuestions(data []byte, offset int, count uint16) (int, error) {
	for i := uint16(0); i < count; i++ {
		_, next, err := decodeName(data, offset)

		if err != nil {
			return 0, err
		}

		if next+4 > len(data) {
			return 0, fmt.Errorf("question goes beyond packet")
		}

		offset = next + 4
	}

	return offset, nil
}

func parseRecord(data []byte, offset int) (DNSRecord, int, error) {
	var record DNSRecord

	name, next, err := decodeName(data, offset)
	if err != nil {
		return record, 0, err
	}

	record.Name = name

	if next+10 > len(data) {
		return record, 0, fmt.Errorf(
			"record header is beyond packet",
		)
	}

	record.Type = binary.BigEndian.Uint16(
		data[next : next+2],
	)

	record.Class = binary.BigEndian.Uint16(
		data[next+2 : next+4],
	)

	record.TTL = binary.BigEndian.Uint32(
		data[next+4 : next+8],
	)

	rdLength := int(
		binary.BigEndian.Uint16(
			data[next+8 : next+10],
		),
	)

	rdataStart := next + 10
	rdataEnd := rdataStart + rdLength

	if rdataEnd > len(data) {
		return record, 0, fmt.Errorf(
			"record data is beyond packet",
		)
	}

	record.Data = data[rdataStart:rdataEnd]
	record.RDataOffset = rdataStart

	return record, rdataEnd, nil
}

func parseAnswers(data []byte, offset int, count uint16) ([]DNSRecord, error) {
	records := make([]DNSRecord, 0, count)
	for i := uint16(0); i < count; i++ {
		record, next, err := parseRecord(data, offset)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
		offset = next
	}

	return records, nil
}

func formatRecord(record DNSRecord, packet []byte, rdataOffset int) (string, bool, error) {

	data := record.Data
	switch record.Type {
	case TypeA:
		if len(data) != 4 {
			return "", false, fmt.Errorf(
				"invalid A record data length",
			)
		}

		ip := net.IP(data).To4()

		if ip == nil {
			return "", false, fmt.Errorf(
				"invalid A address",
			)
		}
		return fmt.Sprintf("answer A %s %d", ip.String(), record.TTL), true, nil

	case TypeAAAA:
		if len(data) != 16 {
			return "", false, fmt.Errorf(
				"invalid AAAA rdata length",
			)
		}
		return fmt.Sprintf("answer AAAA %s %d", net.IP(data).String(), record.TTL), true, nil

	case TypeCNAME:
		name, next, err := decodeName(
			packet,
			rdataOffset,
		)

		if err != nil {
			return "", false, err
		}

		if next > rdataOffset+len(data) {
			return "", false, fmt.Errorf(
				"CNAME exceeds rdata",
			)
		}
		return fmt.Sprintf("answer CNAME %s %d", name, record.TTL), true, nil

	case TypeNS:
		name, next, err := decodeName(
			packet,
			rdataOffset,
		)

		if err != nil {
			return "", false, err
		}

		if next > rdataOffset+len(data) {
			return "", false, fmt.Errorf(
				"NS exceeds rdata",
			)
		}
		return fmt.Sprintf("answer NS %s %d", name, record.TTL), true, nil

	case TypeMX:
		if len(data) < 3 {
			return "", false, fmt.Errorf(
				"invalid MX rdata",
			)
		}

		priority := binary.BigEndian.Uint16(
			data[:2],
		)

		name, next, err := decodeName(
			packet,
			rdataOffset+2,
		)

		if err != nil {
			return "", false, err
		}

		if next > rdataOffset+len(data) {
			return "", false, fmt.Errorf(
				"MX name exceeds rdata",
			)
		}
		return fmt.Sprintf("answer MX %d %s %d", priority, name, record.TTL), true, nil

	case TypeTXT:
		var result strings.Builder

		for pos := 0; pos < len(data); {
			length := int(data[pos])
			pos++

			if pos+length > len(data) {
				return "", false, fmt.Errorf(
					"TXT segment exceeds rdata",
				)
			}

			result.Write(data[pos : pos+length])

			pos += length
		}
		return fmt.Sprintf("answer TXT %s %d", result.String(), record.TTL), true, nil

	// для unsupported
	default:
		return "", false, nil
	}
}

func statusName(flags uint16) string {
	switch flags & 0x000F {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", flags&0x000F)
	}
}

func cacheKey(name string, questionType uint16) string {
	return strings.ToLower(name) + "\x00" + strconv.Itoa(int(questionType))
}

func printResult(queryName string, queryType string, status string, answers []string) {
	fmt.Printf("query %s %s\n", queryName, queryType)
	fmt.Printf("status %s\n", status)

	for _, answer := range answers {
		fmt.Println(answer)
	}

	fmt.Println("end")
}

func processQuery(line string, server string, port int, cache map[string]cacheEntry) error {
	parts := strings.Fields(line)

	if len(parts) != 2 {
		return nil
	}

	queryName := parts[0]
	queryType := parts[1]

	questionType, ok := typeCode(queryType)

	if !ok {
		return nil
	}

	key := cacheKey(queryName, questionType)

	if entry, ok := cache[key]; ok {
		if time.Now().Before(entry.expires) {
			printResult(queryName, queryType, "NOERROR", entry.answers)
			return nil
		}

		delete(cache, key)
	}

	id := newQueryID()
	packet, err := buildQuery(id, queryName, questionType)
	if err != nil {
		return err
	}

	response, err := sendQuery(server, port, packet, id)
	if err != nil {
		if errors.Is(err, errTimeout) {
			fmt.Printf("query %s %s\n", queryName, queryType)

			fmt.Println("status TIMEOUT")
			fmt.Println("end")

			return errTimeout
		}

		return err
	}

	header, err := parseHeader(response)
	if err != nil {
		return err
	}

	if header.ID != id {
		return fmt.Errorf(
			"response ID mismatch",
		)
	}

	status := statusName(header.Flags)
	offset, err := skipQuestions(response, 12, header.QDCount)
	if err != nil {
		return err
	}

	records, err := parseAnswers(response, offset, header.ANCount)
	if err != nil {
		return err
	}

	answers := make([]string, 0, len(records))
	allTTLPositive := len(records) > 0
	minTTL := uint32(^uint32(0))

	for _, record := range records {

		if record.TTL == 0 {
			allTTLPositive = false
		}

		if record.TTL < minTTL {
			minTTL = record.TTL
		}

		line, supported, err := formatRecord(record, response, record.RDataOffset)

		if err != nil {
			return err
		}

		if supported {
			answers = append(answers, line)
		}
	}

	printResult(queryName, queryType, status, answers)
	if status == "NOERROR" &&
		len(records) > 0 &&
		allTTLPositive {

		cache[key] = cacheEntry{answers: answers, expires: time.Now().Add(
			time.Duration(minTTL) * time.Second,
		),
		}
	}

	return nil
}

func typeCode(value string) (uint16, bool) {
	switch strings.ToUpper(value) {
	case "A":
		return TypeA, true

	case "NS":
		return TypeNS, true

	case "CNAME":
		return TypeCNAME, true

	case "MX":
		return TypeMX, true

	case "TXT":
		return TypeTXT, true

	case "AAAA":
		return TypeAAAA, true

	default:
		return 0, false
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(
			os.Stderr,
			"usage: %s <server> <port>\n",
			os.Args[0],
		)

		os.Exit(1)
	}

	server := strings.Trim(
		os.Args[1],
		"[]",
	)

	port, err := parsePort(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if net.ParseIP(server) == nil {
		fmt.Fprintf(
			os.Stderr,
			"invalid server address: %s\n",
			server,
		)

		os.Exit(1)
	}

	cache := make(map[string]cacheEntry)

	scanner := bufio.NewScanner(
		os.Stdin,
	)

	for scanner.Scan() {

		line := strings.TrimSpace(
			scanner.Text(),
		)

		if line == "" {
			continue
		}

		err := processQuery(
			line,
			server,
			port,
			cache,
		)

		if err != nil {
			if errors.Is(err, errTimeout) {
				os.Exit(1)
			}

			fmt.Fprintln(os.Stderr, err)

			os.Exit(1)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)

		os.Exit(1)
	}
}
