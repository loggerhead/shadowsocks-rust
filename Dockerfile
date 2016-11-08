FROM scorpil/rust:stable
ADD . .
RUN cargo build --release \
 && mv ./target/release/shadowsocks /usr/local/bin/ssserver

ENTRYPOINT ["/usr/local/bin/ssserver"]
