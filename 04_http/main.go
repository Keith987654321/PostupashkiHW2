package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type Header struct {
	Name  string
	Value string
}

type Message struct {
	Type    string
	Method  string
	Target  string
	Version string
	Status  string
	Reason  string
	Headers []Header
	Body    []byte
}

func parseMessage(data []byte) (*Message, string) {
	var msg Message
	startEnd := bytes.Index(data, []byte("\r\n"))

	if startEnd == -1 {
		return nil, "bad_start_line"
	}

	startLine := string(data[:startEnd])
	if strings.HasPrefix(startLine, "HTTP/") {
		parts := strings.SplitN(startLine, " ", 3)
		if len(parts) != 3 {
			return nil, "bad_start_line"
		}

		msg.Type = "response"
		msg.Version = parts[0]
		if msg.Version != "HTTP/1.1" {
			return nil, "bad_start_line"
		}

		status, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, "bad_start_line"
		}

		msg.Status = strconv.Itoa(status)
		msg.Reason = parts[2]
	} else {
		parts := strings.SplitN(startLine, " ", 3)

		if len(parts) != 3 {
			return nil, "bad_start_line"
		}

		msg.Type = "request"
		msg.Method = parts[0]
		msg.Target = parts[1]
		msg.Version = parts[2]

		if msg.Version != "HTTP/1.1" {
			return nil, "bad_start_line"
		}
	}

	headerStart := startEnd + 2
	var headerEnd int
	var bodyStart int

	if len(data) >= headerStart+2 &&
		data[headerStart] == '\r' &&
		data[headerStart+1] == '\n' {
		headerEnd = headerStart
		bodyStart = headerStart + 2
	} else {
		headerEndRelative := bytes.Index(
			data[headerStart:],
			[]byte("\r\n\r\n"),
		)

		if headerEndRelative == -1 {
			return nil, "bad_header"
		}

		headerEnd = headerStart + headerEndRelative
		bodyStart = headerEnd + 4
	}

	headerData := data[headerStart:headerEnd]
	if len(headerData) > 0 {
		headerLines := bytes.Split(headerData, []byte("\r\n"))
		for _, line := range headerLines {
			header, ok := parseHeader(line)

			if !ok {
				return nil, "bad_header"
			}

			msg.Headers = append(msg.Headers, header)
		}
	}

	body, reason := parseBody(data[bodyStart:], msg.Headers)
	if reason != "" {
		return nil, reason
	}

	msg.Body = body

	return &msg, ""
}

func parseHeader(line []byte) (Header, bool) {
	colon := bytes.IndexByte(line, ':')
	if colon == -1 {
		return Header{}, false
	}

	name := string(line[:colon])
	if name == "" {
		return Header{}, false
	}

	for i := 0; i < len(name); i++ {
		if !isTokenChar(name[i]) {
			return Header{}, false
		}
	}

	if strings.TrimSpace(name) != name {
		return Header{}, false
	}

	value := strings.Trim(string(line[colon+1:]), " \t")

	return Header{
		Name:  strings.ToLower(name),
		Value: value,
	}, true
}

func isTokenChar(c byte) bool {
	if c >= 'a' && c <= 'z' {
		return true
	}

	if c >= 'A' && c <= 'Z' {
		return true
	}

	if c >= '0' && c <= '9' {
		return true
	}

	switch c {
	case '!', '#', '$', '%', '&', '\'', '*',
		'+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func parseBody(data []byte, headers []Header) ([]byte, string) {
	transferEncoding := ""
	contentLength := -1
	for _, header := range headers {
		switch header.Name {
		case "transfer-encoding":
			transferEncoding = strings.ToLower(strings.TrimSpace(header.Value))
		case "content-length":
			n, err := strconv.Atoi(strings.TrimSpace(header.Value))
			if err != nil || n < 0 {
				return nil, "bad_header"
			}
			contentLength = n
		}
	}

	if transferEncoding == "chunked" {
		return parseChunkedBody(data)
	}

	if contentLength >= 0 {
		if len(data) < contentLength {
			return nil, "incomplete_body"
		}

		return data[:contentLength], ""
	}

	return []byte{}, ""
}

func parseChunkedBody(data []byte) ([]byte, string) {
	var body bytes.Buffer
	pos := 0
	for {
		lineEndRelative := bytes.Index(data[pos:], []byte("\r\n"))
		if lineEndRelative == -1 {
			return nil, "bad_chunk"
		}

		lineEnd := pos + lineEndRelative
		sizeLine := string(data[pos:lineEnd])
		if semicolon := strings.IndexByte(sizeLine, ';'); semicolon != -1 {
			sizeLine = sizeLine[:semicolon]
		}

		sizeLine = strings.TrimSpace(sizeLine)
		if sizeLine == "" {
			return nil, "bad_chunk"
		}

		size, err := strconv.ParseUint(sizeLine, 16, 64)
		if err != nil {
			return nil, "bad_chunk"
		}

		pos = lineEnd + 2

		if size == 0 {
			return body.Bytes(), ""
		}

		if size > uint64(len(data)) {
			return nil, "bad_chunk"
		}

		chunkSize := int(size)
		if len(data)-pos < chunkSize {
			return nil, "bad_chunk"
		}

		body.Write(data[pos : pos+chunkSize])
		pos += chunkSize
		if len(data)-pos < 2 {
			return nil, "bad_chunk"
		}

		if data[pos] != '\r' || data[pos+1] != '\n' {
			return nil, "bad_chunk"
		}

		pos += 2
	}
}

func printMessage(msg *Message) {
	fmt.Printf("type %s\n", msg.Type)
	if msg.Type == "request" {
		fmt.Printf("method %s\n", msg.Method)
		fmt.Printf("target %s\n", msg.Target)
	}
	fmt.Printf("version %s\n", msg.Version)
	if msg.Type == "response" {
		fmt.Printf("status %s\n", msg.Status)
		fmt.Printf("reason %s\n", msg.Reason)
	}

	for _, header := range msg.Headers {
		fmt.Printf("header %s %s\n", header.Name, header.Value)
	}

	fmt.Printf("body.length %d\n", len(msg.Body))
	if len(msg.Body) > 0 && isPrintable(msg.Body) {
		fmt.Printf("body.text %s\n", string(msg.Body))
	}
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 0x20 || b > 0x7E {
			return false
		}
	}

	return true
}

func printError(errText string) {
	fmt.Printf("error %s\n", errText)
	os.Exit(1)
}

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		printError("bad_start_line")
		return
	}

	msg, errReason := parseMessage(data)
	if errReason != "" {
		printError(errReason)
		return
	}

	printMessage(msg)
}
