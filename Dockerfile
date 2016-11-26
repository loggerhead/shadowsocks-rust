FROM scorpil/rust:stable
ADD . .
RUN cargo build --release \
 && mv ./target/release/ssserver /usr/bin/ssserver

ENTRYPOINT ["/usr/bin/ssserver"]
