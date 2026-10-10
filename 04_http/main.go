package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	typeRequest  = "request"
	typeResponse = "response"
)

var (
	errBadStartLine   = errors.New("bad_start_line")
	errBadHeader      = errors.New("bad_header")
	errIncompleteBody = errors.New("incomplete_body")
	errBadChunk       = errors.New("bad_chunk")
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

func parseMessage(data []byte) (*Message, error) {
	var msg Message

	startEnd := bytes.Index(data, []byte("\r\n"))
	if startEnd == -1 {
		return nil, errBadStartLine
	}

	startLine := string(data[:startEnd])

	if strings.HasPrefix(startLine, "HTTP/") {
		parts := strings.SplitN(startLine, " ", 3)
		if len(parts) != 3 {
			return nil, errBadStartLine
		}

		msg.Type = typeResponse
		msg.Version = parts[0]
		if msg.Version != "HTTP/1.1" {
			return nil, errBadStartLine
		}

		if len(parts[1]) != 3 {
			return nil, errBadStartLine
		}
		for i := 0; i < len(parts[1]); i++ {
			if parts[1][i] < '0' || parts[1][i] > '9' {
				return nil, errBadStartLine
			}
		}

		msg.Status = parts[1]
		msg.Reason = parts[2]
	} else {
		parts := strings.SplitN(startLine, " ", 3)
		if len(parts) != 3 {
			return nil, errBadStartLine
		}

		msg.Type = typeRequest
		msg.Method = parts[0]
		msg.Target = parts[1]
		msg.Version = parts[2]

		if msg.Method == "" || msg.Target == "" {
			return nil, errBadStartLine
		}

		for i := 0; i < len(msg.Method); i++ {
			if !isTokenChar(msg.Method[i]) {
				return nil, errBadStartLine
			}
		}

		if msg.Version != "HTTP/1.1" {
			return nil, errBadStartLine
		}
	}

	headerStart := startEnd + 2
	separatorRelative := bytes.Index(
		data[startEnd:],
		[]byte("\r\n\r\n"),
	)
	if separatorRelative == -1 {
		return nil, errBadHeader
	}

	separatorStart := startEnd + separatorRelative
	headerEnd := separatorStart
	bodyStart := separatorStart + 4

	headerData := data[headerStart:headerEnd]

	if len(headerData) > 0 {
		headerLines := bytes.Split(headerData, []byte("\r\n"))

		for _, line := range headerLines {
			header, ok := parseHeader(line)
			if !ok {
				return nil, errBadHeader
			}

			msg.Headers = append(msg.Headers, header)
		}
	}

	body, err := parseBody(data[bodyStart:], msg.Headers, msg.Type, msg.Status)
	if err != nil {
		return nil, err
	}

	msg.Body = body

	return &msg, nil
}

func parseHeader(line []byte) (Header, bool) {
	colon := bytes.IndexByte(line, ':')
	if colon <= 0 {
		return Header{}, false
	}

	name := string(line[:colon])

	for i := 0; i < len(name); i++ {
		if !isTokenChar(name[i]) {
			return Header{}, false
		}
	}

	valueBytes := line[colon+1:]

	for _, b := range valueBytes {
		if (b < 0x20 && b != '\t') || b == 0x7f {
			return Header{}, false
		}
	}

	value := strings.Trim(string(valueBytes), " \t")

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

func parseBody(
	data []byte,
	headers []Header,
	messageType string,
	status string,
) ([]byte, error) {
	var (
		contentLength    = -1
		contentLengthSet bool
		transferEncoding string
		transferSet      bool
	)

	for _, header := range headers {
		switch header.Name {
		case "content-length":
			value := header.Value
			if value == "" {
				return nil, errBadHeader
			}

			for i := 0; i < len(value); i++ {
				if value[i] < '0' || value[i] > '9' {
					return nil, errBadHeader
				}
			}

			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				return nil, errBadHeader
			}

			if contentLengthSet && contentLength != n {
				return nil, errBadHeader
			}

			contentLength = n
			contentLengthSet = true

		case "transfer-encoding":
			if transferSet {
				transferEncoding += "," + header.Value
			} else {
				transferEncoding = header.Value
				transferSet = true
			}
		}
	}

	if messageType == typeRequest && transferSet && contentLengthSet {
		return nil, errBadHeader
	}

	if messageType == typeResponse {
		statusCode, _ := strconv.Atoi(status)
		if (statusCode >= 100 && statusCode < 200) ||
			statusCode == 204 ||
			statusCode == 304 {
			return []byte{}, nil
		}
	}

	if transferSet {
		encodings := strings.Split(strings.ToLower(transferEncoding), ",")
		if len(encodings) == 0 {
			return nil, errBadHeader
		}

		for i := range encodings {
			encodings[i] = strings.TrimSpace(encodings[i])
			if encodings[i] == "" {
				return nil, errBadHeader
			}
		}

		lastEncoding := encodings[len(encodings)-1]

		if lastEncoding == "chunked" {
			return parseChunkedBody(data)
		}

		if messageType == typeRequest {
			return nil, errBadHeader
		}

		return data, nil
	}

	if contentLengthSet {
		if len(data) < contentLength {
			return nil, errIncompleteBody
		}

		return data[:contentLength], nil
	}

	if messageType == typeResponse {
		return data, nil
	}

	return []byte{}, nil
}

func parseChunkedBody(data []byte) ([]byte, error) {
	var body bytes.Buffer
	pos := 0

	for {
		if pos > len(data) {
			return nil, errBadChunk
		}

		lineEndRelative := bytes.Index(data[pos:], []byte("\r\n"))
		if lineEndRelative == -1 {
			return nil, errBadChunk
		}

		lineEnd := pos + lineEndRelative
		sizeLine := string(data[pos:lineEnd])
		if semicolon := strings.IndexByte(sizeLine, ';'); semicolon != -1 {
			sizeLine = sizeLine[:semicolon]
		}

		if sizeLine == "" {
			return nil, errBadChunk
		}

		for i := 0; i < len(sizeLine); i++ {
			c := sizeLine[i]
			if !((c >= '0' && c <= '9') ||
				(c >= 'a' && c <= 'f') ||
				(c >= 'A' && c <= 'F')) {
				return nil, errBadChunk
			}
		}

		size, err := strconv.ParseUint(sizeLine, 16, 64)
		if err != nil {
			return nil, errBadChunk
		}

		pos = lineEnd + 2

		if size == 0 {
			trailerEnd := bytes.Index(data[pos:], []byte("\r\n"))
			if trailerEnd == -1 {
				return nil, errBadChunk
			}

			if trailerEnd == 0 {
				return body.Bytes(), nil
			}

			for {
				trailerEnd = bytes.Index(data[pos:], []byte("\r\n"))
				if trailerEnd == -1 {
					return nil, errBadChunk
				}

				if trailerEnd == 0 {
					return body.Bytes(), nil
				}

				trailerLine := data[pos : pos+trailerEnd]
				if _, ok := parseHeader(trailerLine); !ok {
					return nil, errBadChunk
				}

				pos += trailerEnd + 2
			}
		}

		if size > uint64(len(data)-pos) {
			return nil, errBadChunk
		}

		chunkSize := int(size)
		if len(data)-pos < chunkSize+2 {
			return nil, errBadChunk
		}

		body.Write(data[pos : pos+chunkSize])
		pos += chunkSize

		if data[pos] != '\r' || data[pos+1] != '\n' {
			return nil, errBadChunk
		}

		pos += 2
	}
}

func printMessage(msg *Message) {
	fmt.Printf("type %s\n", msg.Type)

	if msg.Type == typeRequest {
		fmt.Printf("method %s\n", msg.Method)
		fmt.Printf("target %s\n", msg.Target)
	}

	fmt.Printf("version %s\n", msg.Version)

	if msg.Type == typeResponse {
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
		if b < 0x20 || b > 0x7e {
			return false
		}
	}

	return true
}

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	msg, err := parseMessage(data)
	if err != nil {
		fmt.Println("error", err.Error())
		os.Exit(1)
	}

	printMessage(msg)
}
