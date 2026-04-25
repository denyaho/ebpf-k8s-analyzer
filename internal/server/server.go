package server

import (
	"net"
	"fmt"
	"ebpf-k8s-analyzer/internal/handler"
	"ebpf-k8s-analyzer/internal/config"
)

type Server struct {
	addr   string
	config *config.Config
}

func New(addr string, config *config.Config) *Server {
	return &Server{
		addr:   addr,
		config: config,
	}
}

func (s *Server) Start() error{
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("Error starting server: %v", err)
	}
	fmt.Println("Server started on ", s.addr)
	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting connection: ", err.Error())
			continue
		}
		go func(c net.Conn, s *config.Config) {
			handler.HandleConnection(c,s)
		}(conn, s.config)
	}
}

