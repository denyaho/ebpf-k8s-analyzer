FROM golang:1.24-bullseye as builder

RUN apt-get update && apt-get install -y clang llvm libbpf-dev linux-headers-generic curl xz-utils

RUN curl -L -o /tmp/bpftool.tar.gz \
    https://github.com/libbpf/bpftool/releases/download/v7.3.0/bpftool-v7.3.0-amd64.tar.gz

RUN tar -xzf /tmp/bpftool.tar.gz -C /tmp/ && mv /tmp/bpftool /usr/local/bin/bpftool

RUN chmod +x /usr/local/bin/bpftool

WORKDIR /app

COPY . .

RUN go build -o analyzer ./cmd/analyzer/


FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libbpf-dev
WORKDIR /app
COPY --from=builder /app/analyzer .
COPY --from=builder /app/bpf/trace.o ./bpf/

ENTRYPOINT ["./analyzer"]
