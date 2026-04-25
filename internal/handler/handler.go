package handler

import (
	"bufio"
	"fmt"
	"net"
	"strings"

	"ebpf-k8s-analyzer/internal/config"
	"ebpf-k8s-analyzer/internal/parser"
)

func HandleConnection(conn net.Conn, config *config.Config) {
	defer conn.Close()
	fmt.Printf("New connection from: %s\n", conn.RemoteAddr())

	for {
		reader := bufio.NewReader(conn)
		request, err := parser.ParseRequest(reader)
		if err != nil {
			if strings.Contains(err.Error(), "Connection closed by client") {
				fmt.Println("Client disconnected")
				return
			}
			fmt.Printf("Error parsing request: %v\n", err)
			return
		}

		switch request.Method {
		case "GET":
			fmt.Println("Handling GET request")
			HandleGet(request, conn, config)
		case "POST":
			HandlePost(request, conn, config)
		case "DELETE":
			HandleDelete(request, conn, config)
		case "HEAD":
			HandleHead(request, conn, config)
		case "PUT":
			HandlePut(request, conn, config)
		}
		if request.Headers["Connection"] == "close" {
			break
		}
	}
}
