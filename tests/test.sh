#!/bin/bash
work_dir=/tmp
sss_pid_path=/tmp/sss.pid
sss_log_path=/tmp/sss.log
ssc_pid_path=/tmp/ssc.pid
ssc_log_path=/tmp/ssc.log

src_dir=$(pwd)
echo_port=9000
sss_port=8111
ssc_port=8010

# run at crate root directory
cargo build --features "openssl" && mv $src_dir/target/debug/ssserver $work_dir/ssserver
cargo build --features "openssl sslocal" && mv $src_dir/target/debug/ssserver $work_dir/sslocal

python $src_dir/tests/echo_server.py &
cd $work_dir

function get_pid {
    lsof -i :$1 | grep LISTEN | awk '{ print $2 }' | tail -n 1
}

function kill_all {
    kill $(get_pid $echo_port) $(get_pid $ssc_port) $(get_pid $sss_port)
}

function assert {
    echo "$@"
    $command "$@"
    if [ $? -ne 0 ]; then
        echo "failed: $@"
        kill_all
        exit 1
    fi
}

function assert_raise {
    if [ $? -ne 0 ]; then
        echo "$1"
        kill_all
        exit 1
    fi
}

function run_test {
    sss_version=$1
    ssc_version=$2
    sss_conf_name=$3
    ssc_conf_name=$4

    sss_conf=$src_dir/tests/config/$sss_conf_name
    ssc_conf=$src_dir/tests/config/$ssc_conf_name
    sss_cmd=$work_dir/ssserver
    ssc_cmd=$work_dir/sslocal
    if [[ "$sss_version" == "py" ]]; then
        sss_cmd=ssserver
    fi
    if [[ "$ssc_version" == "py" ]]; then
        ssc_cmd=sslocal
    fi

    start_sss_cmd="$sss_cmd -d start -v -c $sss_conf --pid-file $sss_pid_path --log-file $sss_log_path"
    start_ssc_cmd="$ssc_cmd -d start -v -c $ssc_conf --pid-file $ssc_pid_path --log-file $ssc_log_path"

    # start ssserver
    if [[ "$sss_version" == "py" ]]; then
        start_sss_cmd="$start_sss_cmd --forbidden-ip ''"
    fi

    # start ssserver & sslocal
    echo "start ssserver..."
    eval $start_sss_cmd
    assert_raise "ERROR: start ssserver failed ($sss_conf_name)"
    echo "start sslocal..."
    eval $start_ssc_cmd
    assert_raise "ERROR: start sslocal failed ($ssc_conf_name)"

    # test
    assert nosetests -q -x $src_dir/tests/test_tcp.py
    assert nosetests -q -x $src_dir/tests/test_udp.py

    # stop
    echo "stop ssserver..."
    $sss_cmd -d stop --pid-file $sss_pid_path
    assert_raise "ERROR: stop ssserver failed ($sss_conf_name)"
    echo "stop sslocal..."
    # a bug of python version sslocal
    if [[ "$ssc_version" == "py" ]]; then
        kill $(get_pid $ssc_port)
    else
        $ssc_cmd -d stop --pid-file $ssc_pid_path
    fi
    assert_raise "ERROR: stop sslocal failed ($ssc_conf_name)"
    echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
}

# ssserver sslocal
run_test rs rs rs_server.toml rs_local.toml
run_test rs py rs_server.toml ss.json
run_test rs py rs_server.toml ss_ota.json
run_test py rs ss.json rs_local.toml
run_test py rs ss.json rs_local_ota.toml

kill_all
