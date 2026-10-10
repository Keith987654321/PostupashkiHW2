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

	flagQR    uint16 = 1 << 15
	flagRD    uint16 = 1 << 8
	rcodeMask uint16 = 0x000F

	readTimeout     = 5 * time.Second
	maxPointerHops  = 128
	dnsUDPMaxPacket = 512
)

var errTimeout = errors.New("timeout")

var recordTypeNames = map[uint16]string{
	TypeA:     "A",
	TypeNS:    "NS",
	TypeCNAME: "CNAME",
	TypeMX:    "MX",
	TypeTXT:   "TXT",
	TypeAAAA:  "AAAA",
}

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
	status  string
	answers []string
	expires time.Time
}

func encodeName(name string) ([]byte, error) {
	if name == "" {
		return nil, errors.New("empty domain name")
	}
	if name == "." {
		return []byte{0}, nil
	}

	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}, nil
	}

	labels := strings.Split(name, ".")
	result := make([]byte, 0, len(name)+2)
	wireLength := 1

	for _, label := range labels {
		if label == "" {
			return nil, errors.New("empty label in domain name")
		}
		if len(label) > 63 {
			return nil, errors.New("label longer than 63 bytes")
		}

		wireLength += 1 + len(label)
		if wireLength > 255 {
			return nil, errors.New("domain name longer than 255 bytes")
		}

		result = append(result, byte(len(label)))
		result = append(result, label...)
	}

	result = append(result, 0)
	return result, nil
}

func encodeHeader(id uint16) []byte {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], flagRD)
	binary.BigEndian.PutUint16(header[4:6], 1)
	return header
}

func encodeQuestion(name string, questionType uint16) ([]byte, error) {
	question, err := encodeName(name)
	if err != nil {
		return nil, err
	}

	var buf [2]byte
	result := make([]byte, 0, len(question)+4)
	result = append(result, question...)
	binary.BigEndian.PutUint16(buf[:], questionType)
	result = append(result, buf[:]...)
	binary.BigEndian.PutUint16(buf[:], ClassIN)
	result = append(result, buf[:]...)
	return result, nil
}

func buildQuery(id uint16, name string, questionType uint16) ([]byte, error) {
	question, err := encodeQuestion(name, questionType)
	if err != nil {
		return nil, err
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
		return 0, fmt.Errorf("invalid port %q", value)
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

func sendQuery(addr *net.UDPAddr, packet []byte, id uint16, queryName string, questionType uint16, buffer []byte) ([]byte, error) {
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return nil, errTimeout
			}
			return nil, err
		}

		if n < 12 || binary.BigEndian.Uint16(buffer[:2]) != id {
			continue
		}

		response := buffer[:n]
		if !responseMatchesQuery(response, id, queryName, questionType) {
			continue
		}

		return append([]byte(nil), response...), nil
	}
}

func responseMatchesQuery(data []byte, id uint16, queryName string, questionType uint16) bool {
	header, err := parseHeader(data)
	if err != nil || header.ID != id || header.Flags&flagQR == 0 || header.QDCount != 1 {
		return false
	}

	name, next, err := decodeName(data, 12)
	if err != nil || next+4 > len(data) {
		return false
	}

	gotType := binary.BigEndian.Uint16(data[next : next+2])
	gotClass := binary.BigEndian.Uint16(data[next+2 : next+4])
	return normalizeDNSName(name) == normalizeDNSName(queryName) && gotType == questionType && gotClass == ClassIN
}

func parseHeader(data []byte) (DNSHeader, error) {
	if len(data) < 12 {
		return DNSHeader{}, errors.New("packet too short")
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

func decodeName(data []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(data) {
		return "", 0, errors.New("invalid name offset")
	}

	var labels []string
	pos := offset
	nextOffset := -1
	pointerHops := 0
	wireLength := 1 // terminating root label

	for {
		if pos < 0 || pos >= len(data) {
			return "", 0, errors.New("name goes beyond packet")
		}

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
				return "", 0, errors.New("incomplete compression pointer")
			}

			pointerHops++
			if pointerHops > maxPointerHops {
				return "", 0, errors.New("too many compression pointer jumps")
			}

			pointer := int(binary.BigEndian.Uint16(data[pos:pos+2]) & 0x3FFF)
			if nextOffset == -1 {
				nextOffset = pos + 2
			}
			pos = pointer
			continue
		}

		if length&0xC0 != 0 {
			return "", 0, errors.New("invalid label length")
		}

		pos++
		end := pos + int(length)
		if end > len(data) {
			return "", 0, errors.New("label goes beyond packet")
		}

		wireLength += 1 + int(length)
		if wireLength > 255 {
			return "", 0, errors.New("expanded domain name longer than 255 bytes")
		}

		labels = append(labels, escapeDNSLabel(data[pos:end]))
		pos = end
	}
}

func escapeDNSLabel(label []byte) string {
	var result strings.Builder
	for _, b := range label {
		if b >= 0x21 && b <= 0x7E && b != '.' && b != '\\' {
			result.WriteByte(b)
		} else {
			fmt.Fprintf(&result, "\\%03d", b)
		}
	}
	return result.String()
}

func skipQuestions(data []byte, offset int, count uint16) (int, error) {
	for i := uint16(0); i < count; i++ {
		_, next, err := decodeName(data, offset)
		if err != nil {
			return 0, err
		}
		if next+4 > len(data) {
			return 0, errors.New("question goes beyond packet")
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
		return record, 0, errors.New("record header goes beyond packet")
	}

	record.Type = binary.BigEndian.Uint16(data[next : next+2])
	record.Class = binary.BigEndian.Uint16(data[next+2 : next+4])
	record.TTL = binary.BigEndian.Uint32(data[next+4 : next+8])
	rdLength := int(binary.BigEndian.Uint16(data[next+8 : next+10]))

	rdataStart := next + 10
	rdataEnd := rdataStart + rdLength
	if rdataEnd > len(data) {
		return record, 0, errors.New("record data goes beyond packet")
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

func formatRecord(record DNSRecord, packet []byte) (string, bool, error) {
	data := record.Data

	switch record.Type {
	case TypeA:
		if len(data) != net.IPv4len {
			return "", false, errors.New("invalid A record data length")
		}
		ip := net.IP(data).To4()
		if ip == nil {
			return "", false, errors.New("invalid A address")
		}
		return fmt.Sprintf("answer A %s %d", ip.String(), record.TTL), true, nil
	case TypeAAAA:
		if len(data) != net.IPv6len {
			return "", false, errors.New("invalid AAAA record data length")
		}
		return fmt.Sprintf("answer AAAA %s %d", net.IP(data).String(), record.TTL), true, nil
	case TypeCNAME, TypeNS:
		name, next, err := decodeName(packet, record.RDataOffset)
		if err != nil {
			return "", false, err
		}
		if next > record.RDataOffset+len(data) {
			return "", false, errors.New("domain name exceeds record data")
		}
		return fmt.Sprintf("answer %s %s %d", recordTypeNames[record.Type], name, record.TTL), true, nil
	case TypeMX:
		if len(data) < 3 {
			return "", false, errors.New("invalid MX record data")
		}
		priority := binary.BigEndian.Uint16(data[:2])
		name, next, err := decodeName(packet, record.RDataOffset+2)
		if err != nil {
			return "", false, err
		}
		if next > record.RDataOffset+len(data) {
			return "", false, errors.New("MX name exceeds record data")
		}
		return fmt.Sprintf("answer MX %d %s %d", priority, name, record.TTL), true, nil
	case TypeTXT:
		var result strings.Builder
		for pos := 0; pos < len(data); {
			length := int(data[pos])
			pos++
			if pos+length > len(data) {
				return "", false, errors.New("TXT segment exceeds record data")
			}
			result.WriteString(escapeTXT(data[pos : pos+length]))
			pos += length
		}
		return fmt.Sprintf("answer TXT %s %d", result.String(), record.TTL), true, nil
	default:
		return "", false, nil
	}
}

func escapeTXT(data []byte) string {
	var result strings.Builder
	for _, b := range data {
		if b >= 0x20 && b <= 0x7E && b != '\\' {
			result.WriteByte(b)
		} else {
			fmt.Fprintf(&result, "\\%03d", b)
		}
	}
	return result.String()
}

func statusName(flags uint16) string {
	switch flags & rcodeMask {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", flags&rcodeMask)
	}
}

func normalizeDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func cacheKey(name string, questionType uint16) string {
	return normalizeDNSName(name) + "\x00" + strconv.Itoa(int(questionType))
}

func printResult(queryName, queryType, status string, answers []string) {
	fmt.Printf("query %s %s\n", queryName, queryType)
	fmt.Printf("status %s\n", status)
	for _, answer := range answers {
		fmt.Println(answer)
	}
	fmt.Println("end")
}

func processQuery(line string, addr *net.UDPAddr, buffer []byte, cache map[string]cacheEntry) error {
	parts := strings.Fields(line)
	if len(parts) != 2 {
		return fmt.Errorf("invalid query %q: expected <name> <type>", line)
	}

	queryName := parts[0]
	queryType := parts[1]
	questionType, ok := typeCode(queryType)
	if !ok {
		return fmt.Errorf("unknown query type %q", queryType)
	}

	key := cacheKey(queryName, questionType)
	if entry, ok := cache[key]; ok {
		if time.Now().Before(entry.expires) {
			printResult(queryName, queryType, entry.status, entry.answers)
			return nil
		}
		delete(cache, key)
	}

	id := newQueryID()
	packet, err := buildQuery(id, queryName, questionType)
	if err != nil {
		return fmt.Errorf("cannot build query for %q: %w", queryName, err)
	}

	response, err := sendQuery(addr, packet, id, queryName, questionType, buffer)
	if err != nil {
		if errors.Is(err, errTimeout) {
			printResult(queryName, queryType, "TIMEOUT", nil)
			return errTimeout
		}
		return fmt.Errorf("query %s %s: %w", queryName, queryType, err)
	}

	header, err := parseHeader(response)
	if err != nil {
		return err
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
	minTTL := ^uint32(0)

	for _, record := range records {
		if record.TTL == 0 {
			allTTLPositive = false
		}
		if record.TTL < minTTL {
			minTTL = record.TTL
		}

		answer, supported, err := formatRecord(record, response)
		if err != nil {
			return err
		}
		if supported {
			answers = append(answers, answer)
		}
	}

	printResult(queryName, queryType, status, answers)

	if status == "NOERROR" && len(records) > 0 && allTTLPositive {
		cache[key] = cacheEntry{
			status:  status,
			answers: answers,
			expires: time.Now().Add(time.Duration(minTTL) * time.Second),
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
		fmt.Fprintf(os.Stderr, "usage: %s <server> <port>\n", os.Args[0])
		os.Exit(1)
	}

	server := strings.Trim(os.Args[1], "[]")
	ip := net.ParseIP(server)
	if ip == nil {
		fmt.Fprintf(os.Stderr, "invalid server address: %s\n", server)
		os.Exit(1)
	}

	port, err := parsePort(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	addr := &net.UDPAddr{IP: ip, Port: port}
	buffer := make([]byte, dnsUDPMaxPacket)
	cache := make(map[string]cacheEntry)
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if err := processQuery(line, addr, buffer, cache); err != nil {
			if errors.Is(err, errTimeout) {
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
