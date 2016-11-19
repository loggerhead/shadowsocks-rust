#!/bin/bash
# run at crate root directory
cargo build --features "openssl" && mv target/debug/ssserver tests/ssserver
cargo build --features "openssl sslocal" && mv target/debug/ssserver tests/sslocal

cd tests/
python echo_server.py &

function assert {
    echo "testing: $command $@"
    $command "$@"
    if [ $? -ne 0 ]; then
        echo "failed: $command $@"
        exit 1
    fi
}

function assert_raise {
    if [ $? -ne 0 ]; then
        echo "$1"
        exit 1
    fi
}

function run_test {
    server_version=$1
    client_version=$2
    server_conf=config/$3
    client_conf=config/$4

    if [[ "$server_version" == "rs" ]]; then
        ./ssserver -d restart -c "$server_conf" --pid-file /tmp/sss_rs.pid --log-file /tmp/sss_rs.log
    elif [[ "$server_version" == "py" ]]; then
        ssserver -d restart -c "$server_conf" --pid-file /tmp/sss_py.pid --log-file /tmp/sss_py.log
    fi
    assert_raise "start ssserver failed"

    if [[ "$client_version" == "rs" ]]; then
        ./sslocal -d restart -c "$client_conf" --pid-file /tmp/ssc_rs.pid --log-file /tmp/ssc_rs.log
    elif [[ "$client_version" == "py" ]]; then
        sslocal -d restart -c "$client_conf" --pid-file /tmp/ssc_py.pid --log-file /tmp/ssc_py.log
    fi
    assert_raise "start sslocal failed"

    assert nosetests test_tcp.py
    assert nosetests test_udp.py
}

run_test rs rs rs_server.toml rs_local.toml
run_test rs py rs_server.toml ss.json
run_test rs py rs_server.toml ss_ota.json
run_test py rs ss.json rs_local.toml
run_test py rs ss.json rs_local_ota.toml
