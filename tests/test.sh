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
    server_cmd=
    client_cmd=

    if [[ "$server_version" == "rs" ]]; then
        server_cmd=./ssserver
    elif [[ "$server_version" == "py" ]]; then
        server_cmd=ssserver
    fi
    if [[ "$client_version" == "rs" ]]; then
        client_cmd=./sslocal
    elif [[ "$client_version" == "py" ]]; then
        client_cmd=sslocal
    fi

    $server_cmd -d start -c "$server_conf" --pid-file /tmp/sss.pid --log-file /tmp/sss.log
    assert_raise "start ssserver failed"
    $client_cmd -d start -c "$client_conf" --pid-file /tmp/ssc_rs.pid --log-file /tmp/ssc_rs.log
    assert_raise "start sslocal failed"
    assert nosetests test_tcp.py
    assert nosetests test_udp.py
    $server_cmd -d stop
    assert_raise "stop ssserver failed"
    $client_cmd -d stop
    assert_raise "stop sslocal failed"
}

run_test rs rs rs_server.toml rs_local.toml
run_test rs py rs_server.toml ss.json
run_test rs py rs_server.toml ss_ota.json
run_test py rs ss.json rs_local.toml
run_test py rs ss.json rs_local_ota.toml
