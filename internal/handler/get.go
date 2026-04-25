package handler

import (
	"ebpf-k8s-analyzer/internal/parser"
	"ebpf-k8s-analyzer/internal/config"
	"net"
	"strings"
	"ebpf-k8s-analyzer/internal/response"
	"fmt"
)

var SupportedEncoding = map[string]bool{
	"gzip": true,
	"deflate": true,
}

func HandleGet(request *parser.Request, conn net.Conn, config *config.Config) {
	res := &response.Response{
		Headers: make(map[string]string),
	}
	fmt.Printf("Handling GET request for path: %s\n", request.Path)
	if request.Path == "/" {
		response.HandleRoot(res)
	}else if strings.HasPrefix(request.Path, "/echo/") {
		response.HandleEcho(res, request)
	}else if request.Path == "/user-agent" {
		response.HandleUserAgent(res, request)
	}else if strings.HasPrefix(request.Path, "/files"){
		if parser.Check_traversal(request.Path) {
			response.HandleBadRequest(res)
			keepalive := request.Headers["Connection"] != "close"
			res.Write(conn, keepalive, false)
			return
		}
		response.HandleFiles(res, request, config)
	}else{
		fmt.Println("Path not found: ", request.Path)
		response.HandleNotFound(res)
	}
	
	keepalive := request.Headers["Connection"] != "close"
	res.Write(conn, keepalive, false)
}