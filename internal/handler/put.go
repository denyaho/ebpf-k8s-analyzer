package handler

import (
	"net"
	"os"

	"ebpf-k8s-analyzer/internal/config"
	"ebpf-k8s-analyzer/internal/parser"
	"ebpf-k8s-analyzer/internal/response"
	"strings"
	"path/filepath"
)

func HandlePut(request *parser.Request, conn net.Conn, config *config.Config) {
	res := &response.Response{
		Headers: make(map[string]string),
	}
	directory := config.DirName
	if directory == "" {
		response.HandleServerError(res)
		res.Write(conn, false, false)
		return
	}
	if strings.HasPrefix(request.Path, "/files/") {
		cleanPath := filepath.Clean(request.Path)
		if parser.Check_traversal(cleanPath) {
			response.HandleBadRequest(res)
			keepalive := request.Headers["Connection"] != "close"
			res.Write(conn, keepalive, false)
			return
		}
		filename := strings.TrimPrefix(cleanPath, "/files/")
		if filename == "" {
			response.HandleBadRequest(res)
			res.Write(conn, false, false)
			return
		}
		file_path := filepath.Join(directory, filename)
		_, err := os.Stat(file_path)
		if err != nil {
			err_new := os.WriteFile(file_path, []byte(request.Body), 0644)
			if err_new != nil {
				response.HandleServerError(res)
			} else {
				response.HandleFileCreate(res)
			}
		} else {
			err1 := os.WriteFile(file_path, []byte(request.Body), 0644)
				if err1 != nil {
					response.HandleServerError(res)
				} else {
					response.HandleFileUpdate(res, request.Body)
				}
		}
		keepalive := request.Headers["Connection"] != "close"
		res.Write(conn, keepalive, false)
	}
}
