package handler

import (
	"net"
	"os"
	"path/filepath"
	"strings"

	"ebpf-k8s-analyzer/internal/config"
	"ebpf-k8s-analyzer/internal/parser"
	"ebpf-k8s-analyzer/internal/response"
	"fmt"
)

func HandlePost(request *parser.Request, conn net.Conn, config *config.Config) {
	res := &response.Response{
		Headers: make(map[string]string),
	}
	directory := config.DirName
	fmt.Println("Handling POST request for path: ", request.Path)
	fmt.Println("directory: ", directory)
	if directory == "" {
		response.HandleServerError(res)
		res.Write(conn, false, false)
		return
	}
	if strings.HasPrefix(request.Path, "/files/"){
		cleanPath := filepath.Clean(request.Path)
		fmt.Println("Handling POST request for path: ", cleanPath)
		if parser.Check_traversal(cleanPath) {
			response.HandleBadRequest(res)
			keepalive := request.Headers["Connection"] != "close"
			res.Write(conn, keepalive, false)
			return
		}
		file_name := strings.TrimPrefix(cleanPath, "/files/")
		if file_name == ""{
			response.HandleBadRequest(res)
			res.Write(conn, false, false)
			return
		}
		file_path := filepath.Join(directory, file_name)
		if _, err := os.Stat(file_path); err == nil {
			response.HandleConflict(res)
			res.Write(conn, false, false)
			return
		}
		err := os.WriteFile(file_path, []byte(request.Body), 0644)
		if err != nil {
			response.HandleServerError(res)
		}else{
			response.HandleFileCreate(res)
		}
		keepalive := request.Headers["Connection"] != "close"
		res.Write(conn, keepalive, false)
	}
}
