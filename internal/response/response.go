package response

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net"

	"os"
	"path/filepath"
	"strings"

	"ebpf-k8s-analyzer/internal/config"
	"ebpf-k8s-analyzer/internal/parser"
)

var SupportedEncodings = map[string]bool{
	"gzip":    true,
	"deflate": true,
}

type Response struct {
	Version    string
	StatusCode int
	StatusText string
	Headers    map[string]string
	Body       []byte
}

func HandleRoot(response *Response) {
	response.StatusCode = 200
	response.StatusText = "OK"
	response.Headers["Content-Type"] = "text/plain"
}

func HandleEcho(response *Response, request *parser.Request) {
	words := request.Path[len("/echo/"):]
	encoding, ok := request.Headers["Accept-Encoding"]
	if ok {
		encodings := strings.Split(encoding, ",")
		encode := "invalid-encoding"
		for _, e := range encodings {
			if SupportedEncodings[strings.TrimSpace(e)] {
				encode = strings.TrimSpace(e)
				break
			}
		}
		switch encode {
		case "gzip":
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			if _, err := zw.Write([]byte(words)); err != nil {
				response.StatusCode = 500
				response.StatusText = "Internal Server Error"
				return
			}
			zw.Close()
			compressed := buf.Bytes()
			response.StatusCode = 200
			response.StatusText = "OK"
			response.Headers["Content-Type"] = "Text/plain"
			response.Headers["Content-Encoding"] = "gzip"
			response.Headers["Content-Length"] = fmt.Sprintf("%d", len(compressed))
			response.Body = compressed
		default:
			response.StatusCode = 200
			response.StatusText = "OK"
			response.Headers["Content-Type"] = "text/plain"
			response.Headers["Content-Length"] = fmt.Sprintf("%d", len(words))
			response.Body = []byte(words)
		}
	} else {
		response.StatusCode = 200
		response.StatusText = "OK"
		response.Headers["Content-Type"] = "text/plain"
		response.Headers["Content-Length"] = fmt.Sprintf("%d", len(words))
		response.Body = []byte(words)
	}
}

func HandleUserAgent(response *Response, request *parser.Request) {
	response.StatusCode = 200
	response.StatusText = "OK"
	response.Headers["Content-Type"] = "text/plain"
	response.Headers["User-Agent"] = request.Headers["User-Agent"]
	response.Headers["Content-Length"] = fmt.Sprintf("%d", len(request.Headers["User-Agent"]))
	response.Body = []byte(request.Headers["User-Agent"])
}

func HandleFiles(response *Response, request *parser.Request, config *config.Config) {

	directory := config.DirName
	if directory == "" {
		response.StatusCode = 500
		response.StatusText = "Internal Server Error"
		return
	}
	file_name := request.Path[len("/files/"):]
	full_path := filepath.Join(directory, file_name)
	data, err := os.ReadFile(full_path)
	if err != nil {
		response.StatusCode = 404
		response.StatusText = "Not Found"
		return
	}
	response.StatusCode = 200
	response.StatusText = "OK"
	response.Headers["Content-Type"] = "application/octet-stream"
	response.Headers["Content-Length"] = fmt.Sprintf("%d", len(data))
	response.Body = data
}

func HandleNotFound(response *Response) {
	response.StatusCode = 404
	response.StatusText = "Not Found"
}

func HandleServerError(response *Response) {
	response.StatusCode = 500
	response.StatusText = "Internal Server Error"
}

func HandleFileCreate(response *Response) {
	response.StatusCode = 201
	response.StatusText = "Created"
}

func HandleFileUpdate(response *Response, body []byte) {
	response.StatusCode = 200
	response.StatusText = "OK"
	response.Body = body
}

func HandleConflict(response *Response) {
	response.StatusCode = 409
	response.StatusText = "Conflict"
}

func HandleBadRequest(response *Response) {
	response.StatusCode = 400
	response.StatusText = "Bad Request"
}

func HandleFileDelete(response *Response) {
	response.StatusCode = 204
	response.StatusText = "No Content"
}

func (r *Response) Write(conn net.Conn, keepAlive bool, head bool) {
	r.Version = "HTTP/1.1"
	if keepAlive {
		r.Headers["Connection"] = "keep-alive"
	} else {
		r.Headers["Connection"] = "close"
	}
	status_line := fmt.Sprintf("%s %d %s\r\n", r.Version, r.StatusCode, r.StatusText)
	
	header_lines := fmt.Sprintf("Connection: %s\r\nContent-Length: %d\r\n", r.Headers["Connection"], 0)
	switch r.StatusCode {
	case 200:
		header_lines := fmt.Sprintf("Content-Type: %s\r\nContent-Length: %d\r\nConnection: %s\r\n", r.Headers["Content-Type"], len(r.Body), r.Headers["Connection"])
		if r.Body == nil && r.Headers == nil {
			conn.Write([]byte(status_line + "\r\n"))
			return
		} else if r.Headers["Content-Encoding"] != "" {
			header_lines = header_lines + fmt.Sprintf("Content-Encoding: %s\r\n", r.Headers["Content-Encoding"])
		} else if head == true {
			conn.Write([]byte(status_line + header_lines + "\r\n"))
			return
		}
		body_line := fmt.Sprintf("%s\r\n", r.Body)
		fmt.Println("status_line: ", body_line)
		conn.Write([]byte(status_line + header_lines + body_line + "\r\n"))
	case 201:
		conn.Write([]byte(status_line + header_lines + "\r\n"))
	case 204:
		conn.Write([]byte(status_line + header_lines + "\r\n"))
	case 400:
		conn.Write([]byte(status_line + header_lines + "\r\n"))
	case 409:
		conn.Write([]byte(status_line + header_lines + "\r\n"))
	case 404:
		conn.Write([]byte(status_line + header_lines + "\r\n"))
	case 500:
		conn.Write([]byte(status_line + header_lines + "\r\n"))
	}
}
