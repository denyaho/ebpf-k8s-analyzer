package main

import (
<<<<<<< HEAD
	"encoding/binary"
=======
>>>>>>> ac2487919706e208c473eb4c75b09d7ef2922d09
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
<<<<<<< HEAD
	"net"
=======
>>>>>>> ac2487919706e208c473eb4c75b09d7ef2922d09

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
<<<<<<< HEAD
	"github.com/cilium/ebpf/ringbuf"

)

type Event struct {
	SrcIP  uint32
	DstIP  uint32
	DstPort uint16
}

=======
)

>>>>>>> ac2487919706e208c473eb4c75b09d7ef2922d09
func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}
<<<<<<< HEAD
	spec, err := ebpf.LoadCollectionSpec("bpf/trace.o")//ELFファイルをロードして、eBPFプログラムとマップの仕様を取得します
=======

	spec, err := ebpf.LoadCollectionSpec("bpf/trace.o")
>>>>>>> ac2487919706e208c473eb4c75b09d7ef2922d09
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
		event.DstPort = binary.LittleEndian.Uint16(record.RawSample[8:10])
		fmt.Printf("%-20s -> %-20s port %d\n",
			net.IP(record.RawSample[0:4]).String(),
			net.IP(record.RawSample[4:8]).String(),
			event.DstPort,
		)
	}
}
