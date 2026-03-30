問題2：vmlinux.hが取得できなかった
eBPFプログラムのコンパイルにはカーネルの型情報が全て入ったvmlinux.hが必要。これをGitHubから落とそうとしたが404になった。正しくは動いているカーネルからbpftoolで生成する必要がある。
bash# これが正しいやり方
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
問題3：bpftoolのバージョンが古かった
aptで入るbpftoolはv5系で、minikubeのカーネル（6.6系）のBTF形式を読めなかった。GitHubからv7.3.0を直接取得することで解決。
問題4：__arrayマクロの誤用
eBPFのmap定義に__arrayを使っていたが、これは配列型の値を定義するもの。mapのtypeやサイズは数値なので__uintを使う必要があった。またBPF_MAP_TYPE_RINGBUFを使うことで、カーネルとユーザ空間でメモリを直接共有でき、オーバーヘッドを最小化できる

# ビルドコマンド
docker run --rm --privileged -v /sys:/sys ebpf-builder \
  bash -c "bpftool btf dump file /sys/kernel/btf/vmlinux format c > /app/bpf/vmlinux.h && \
  clang -O2 -g -target bpf -I/app/bpf -c /app/bpf/trace.c -o /app/bpf/trace.o"