package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"net"
	"net/http"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Event struct {
	SrcIP  uint32
	DstIP  uint32
	DstPort uint16
}

var (
	tcpConnectCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tcp_connect_total",
			Help: "Total number of tcp_connect events",
		},
		[]string{"dst_ip", "dst_port"},

	)
)

func init() {
	prometheus.MustRegister(tcpConnectCounter)
}


func main() {

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Println("Metrics server listening on :2112")
		if err := http.ListenAndServe(":2112", nil); err != nil {
			log.Fatalf("Failed to start metrics server: %v", err)
		}
	}()


	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpec("bpf/trace.o")//ELFファイルをロードして、eBPFプログラムとマップの仕様を取得します

	if err != nil {
		log.Fatalf("Failed to load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Verifier error: \n%-v", ve)
		}
		log.Fatalf("Failed to create collection: %v", err)
	}
	defer coll.Close()

	probe, err := link.Kprobe("tcp_connect", coll.Programs["trace_connect"], nil)
	if err != nil {
		log.Fatalf("Failed to attach kprobe: %v", err)
	}
	defer probe.Close()

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatal("Failed to open ringbuf reader:", err)
	}
	defer rd.Close()

	fmt.Println("Tracing tcp_connect... Press Ctrl+C to stop.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<- sig
		rd.Close() // シグナルを受け取ったらリングバッファリーダーを閉じて、ループを終了させる
	}()
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("Errro reading from ringbuf: %v", err)
			continue
		}
		var event Event
		event.SrcIP = binary.LittleEndian.Uint32(record.RawSample[0:4])
		event.DstIP = binary.LittleEndian.Uint32(record.RawSample[4:8])
		event.DstPort = binary.BigEndian.Uint16(record.RawSample[8:10])
		fmt.Printf("%-20s -> %-20s port %d\n",
			net.IP(record.RawSample[0:4]).String(),
			net.IP(record.RawSample[4:8]).String(),
			event.DstPort,
		)
		tcpConnectCounter.WithLabelValues(
			net.IP(record.RawSample[4:8]).String(),
			fmt.Sprintf("%d", event.DstPort),
		).Inc()
	}
}
