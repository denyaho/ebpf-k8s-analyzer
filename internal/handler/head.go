package handler

import (
	"net"
	"strings"

	"ebpf-k8s-analyzer/internal/config"
	"ebpf-k8s-analyzer/internal/parser"
	"ebpf-k8s-analyzer/internal/response"
)

func HandleHead(request *parser.Request, conn net.Conn, config *config.Config) {
	res := &response.Response{
		Headers: make(map[string]string),
	}
	if request.Path == "/" {
		response.HandleRoot(res)
	} else if strings.HasPrefix(request.Path, "/echo/") {
		response.HandleEcho(res, request)
	} else if request.Path == "/user-agent" {
		response.HandleUserAgent(res, request)
	} else if strings.HasPrefix(request.Path, "/files") {
		response.HandleFiles(res, request, config)
	} else {
		response.HandleNotFound(res)
	}
	keepalive := request.Headers["Connection"] != "close"
	res.Write(conn, keepalive, true)
}
