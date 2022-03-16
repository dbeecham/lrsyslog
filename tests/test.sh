#!/usr/bin/env bash

set -eou pipefail

test_basic_log() {
    printf "<158>1 2022-03-14T09:39:50.824885+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 1 - -  src/gwyinit.c:933:gwyinit_sigwait: signal 17 cought...\n" | socat -d - tcp:127.0.0.1:30514
}

test_multiple_log() {
    printf "<158>1 2022-03-14T09:39:50.824885+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 1 - -  src/gwyinit.c:933:gwyinit_sigwait: signal 17 cought...\n<158>1 2022-03-14T09:39:50.824885+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 1 - -  src/gwyinit.c:933:gwyinit_sigwait: signal 17 cought...\n" | socat -d - tcp:127.0.0.1:30514
}

test_partial_log() {
    ( printf "<158>1 2022-03-14T09:39:50.824885+00:00 0d182d364752354b gwyi"; sleep 0.2;
      printf "nit-81253471b07a140b5de7da2 1 - -  src/gwyinit.c:933:gwyinit_"; sleep 0.2; 
      printf "sigwait: signal 17 cought...\n<158>1 2022-03-14T09:39:50.8248"; sleep 0.2;
      printf "85+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 1 - -  src/gwyinit.c:933:gwyinit_sigwait: signal 17 cought...\n") | socat -d - tcp:127.0.0.1:30514
}

test_this_log() {
    printf "<46>1 2022-03-16T17:42:21.462632+00:00 022717415432394b  - - -  action 'action-0-builtin:omfwd' resumed (module 'builtin:omfwd') [v8.38.0 try http://www.rsyslog.com/e/2359 ]\n<43>1 2022-03-16T17:42:19.490069+00:00 0a270c4a3931394b  - - -  omfwd: TCPSendBuf error -2027, destruct TCP Connection to 127.0.0.1:514 [v8.38.0 try http://www.rsyslog.com/e/2027 ]\n" | socat -d - tcp:127.0.0.1:30514
}


main() {
    test_basic_log
    test_multiple_log
    test_partial_log
    test_this_log
}

main "$@"
