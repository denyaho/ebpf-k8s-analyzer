package parser

import (
	"bufio"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
)

type Request struct {
	Method  string
	Path    string
	Version string
	Headers map[string]string
	Body    []byte
}

func ParseRequest(reader *bufio.Reader) (*Request, error) {
	req := Request{
		Headers: make(map[string]string),
	}

	request_line, err := reader.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("Connection closed by client")
		}
		return nil, fmt.Errorf("Error reading request: %v", err)
	}

	// 空行やCRLFのみの場合をチェック
	if len(strings.TrimSpace(request_line)) == 0 {
		return nil, fmt.Errorf("Empty request line")
	}
	request_slice := strings.Fields(request_line)
	if len(request_slice) < 3 {
		return nil, fmt.Errorf("Invalid request line format: %q", request_line)
	}
	req.Method = request_slice[0]
	req.Path = filepath.Clean(request_slice[1])
	req.Version = request_slice[2]

	for {
		line, _ := reader.ReadString('\n')
		if line == "\r\n" {
			break
		}
		header := strings.Split(line, ": ")
		req.Headers[header[0]] = strings.TrimSpace(header[1])
	}
	content_length, _ := strconv.Atoi(req.Headers["Content-Length"])
	buf := make([]byte, content_length)
	io.ReadFull(reader, buf)

	req.Body = buf
	fmt.Printf("Parsed request: Method=%s, Path=%s, Version=%s, Headers=%v, Body=%s\n", req.Method, req.Path, req.Version, req.Headers, string(req.Body))
	return &req, nil
}

func Check_traversal(path string) bool {
	cleanPath := filepath.Clean(path)
	filename := strings.TrimPrefix(cleanPath, "/files/")
	if strings.Contains(filename, "..") || strings.HasPrefix(filename, "/") {
		return true
	}
	return false
}
