#!/usr/bin/env bash

set -eou pipefail

test_bench() {
    while true; do
        printf "<158>1 2022-03-14T09:39:50.824885+00:00 0d182d364752354b gwyi";
        printf "nit-81253471b07a140b5de7da2 1 - -  src/gwyinit.c:933:gwyinit_";
        printf "sigwait: signal 17 cought...\n<158>1 2022-03-14T09:39:50.8248";
        printf "85+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 1 - -  src/gwyinit.c:933:gwyinit_sigwait: signal 17 cought...\n";
    done | socat -d - tcp:127.0.0.1:30514
}

main() {
    test_bench
}

main "$@"
