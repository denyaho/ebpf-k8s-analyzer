package handler

import (
	"net"
	"os"
	"strings"
	"path/filepath"
	"ebpf-k8s-analyzer/internal/config"
	"ebpf-k8s-analyzer/internal/parser"
	"ebpf-k8s-analyzer/internal/response"
)


func HandleDelete(request *parser.Request, conn net.Conn, config *config.Config) {
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
		if parser.Check_traversal(request.Path) {
			response.HandleBadRequest(res)
			keepalive := request.Headers["Connection"] != "close"
			res.Write(conn, keepalive, false)
			return
		}
		filename := request.Path[len("/files/"):]
		file_path := filepath.Join(directory, filename)
		err := os.Remove(file_path)	
		if err != nil {
			response.HandleNotFound(res)
		} else {
			response.HandleFileDelete(res)
		}
	} else {
		response.HandleNotFound(res)
	}
	keepalive := request.Headers["Connection"] != "close"
	res.Write(conn, keepalive, false)
}
