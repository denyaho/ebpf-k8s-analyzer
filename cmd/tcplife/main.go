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
	SrcIP	 uint32
	DstIP	 uint32
	SrcPort  uint16
	DstPort  uint16
	Timestamp uint64	
}

var (
	tcpConnectLatencyHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "tcp_connect_latency_seconds",
			Help: "Latency of TCP connections in seconds",
			Buckets: []float64{2, 5, 10,50, 100, 500, 1000},
		},
		[]string{"dst_ip", "dst_port"},
	)
)

func init() {
	prometheus.MustRegister(tcpConnectLatencyHistogram)
}

func main() {

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(":2113", nil); err != nil {
			log.Fatalf("Failed to start metrics server: %v", err)
		}
	}()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec("bpf/tcplife.o")
	if err != nil {
		log.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal(err)
	}
	defer coll.Close()

	open_connect, err := link.AttachTracing(link.TracingOptions{
		Program: coll.Programs["tcp_connect"],
	})
	if err != nil {
		log.Fatal(err)
	}
	defer open_connect.Close()

	close_connect, err := link.AttachTracing(link.TracingOptions{
		Program: coll.Programs["tcp_close"],
	})
	if err != nil {
		log.Fatal(err)
	}
	defer close_connect.Close()

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatal("Failed to open ringbuf reader:", err)
	}
	defer rd.Close()

	fmt.Println("Tracing TCP connections... Press Ctrl+C to stop.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<- sig
		rd.Close()
	}()
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("Error reading from ringbuf: %v", err)
			continue
		}
		var event Event
		event.SrcIP = binary.LittleEndian.Uint32(record.RawSample[0:4])
		event.DstIP = binary.LittleEndian.Uint32(record.RawSample[4:8])
		event.Timestamp = binary.LittleEndian.Uint64(record.RawSample[8:16])
		event.SrcPort = binary.BigEndian.Uint16(record.RawSample[16:18])
		event.DstPort = binary.BigEndian.Uint16(record.RawSample[18:20])
		fmt.Printf("Src: %-20s:%d ->Dst:  %-20s:%d latency: %d ms\n",
			net.IP(record.RawSample[0:4]).String(),
			event.SrcPort,
			net.IP(record.RawSample[4:8]).String(),
			event.DstPort,
			event.Timestamp/1000000,
		)

		tcpConnectLatencyHistogram.WithLabelValues(
			net.IP(record.RawSample[4:8]).String(),
			fmt.Sprintf("%d", event.DstPort),
		).Observe(float64(event.Timestamp) / 1e9)
	}
}