#!/usr/bin/env bash

cargo build
time ./target/debug/io_uring_scanner --port 80 -i "173.245.48.1/32" --ring-size 1 tcp-connect