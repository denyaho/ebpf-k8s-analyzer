package main

import (
	"net"
	"os"
	"ebpf-k8s-analyzer/internal/server"
	"ebpf-k8s-analyzer/internal/config"
)


// Ensures gofmt doesn't remove the "net" and "os" imports above (feel free to remove this!)
var _ = net.Listen
var _ = os.Exit

const http_version = "HTTP/1.1"

func main() {
	config := config.ConfigParse(os.Args)
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	server := server.New("0.0.0.0:4221", config)
	server.Start()
	// TODO: Uncomment the code below to pass the first stage
	//

}
