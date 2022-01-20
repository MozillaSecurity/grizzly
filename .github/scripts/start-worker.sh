#!/bin/sh -e

[ -z "$TASKCLUSTER_ACCESS_TOKEN" ] && echo "Missing TASKCLUSTER_ACCESS_TOKEN" >&2 && exit 2
[ -z "$TC_WORKER_ID" ] && echo "Missing TC_WORKER_ID" >&2 && exit 2

set -x

TC_VERSION=v44.4.0
TC_PROJECT=fuzzing
TC_WORKER_TYPE=ci-osx
TC_IDLE_TIMEOUT=300

TASKCLUSTER_ROOT_URL="https://community-tc.services.mozilla.com"
TASKCLUSTER_CLIENT_ID="project/$TC_PROJECT/worker-$TC_WORKER_TYPE-gh"

set +x
cat > worker.config <<EOF
{
  "accessToken": "$TASKCLUSTER_ACCESS_TOKEN",
  "clientId": "$TASKCLUSTER_CLIENT_ID",
  "disableReboots": true,
  "ed25519SigningKeyLocation": "worker.key",
  "idleTimeoutSecs": $TC_IDLE_TIMEOUT,
  "livelogExecutable": "$PWD/livelog",
  "provisionerId": "proj-$TC_PROJECT",
  "publicIP": "127.0.0.1",
  "requiredDiskSpaceMegabytes": 512,
  "rootURL": "$TASKCLUSTER_ROOT_URL",
  "sentryProject": "generic-worker",
  "taskclusterProxyExecutable": "$PWD/taskcluster-proxy",
  "taskclusterProxyPort": 8080,
  "tasksDir": "tasks",
  "workerGroup": "proj-$TC_PROJECT",
  "workerId": "$TC_WORKER_ID",
  "workerType": "$TC_WORKER_TYPE",
  "wstAudience": "communitytc",
  "wstServerURL": "https://community-websocktunnel.services.mozilla.com"
}
EOF
set -x
unset TASKCLUSTER_ACCESS_TOKEN

curl -sSL "https://github.com/taskcluster/taskcluster/releases/download/$TC_VERSION/generic-worker-simple-darwin-amd64" -o generic-worker
curl -sSL "https://github.com/taskcluster/taskcluster/releases/download/$TC_VERSION/livelog-darwin-amd64" -o livelog
curl -sSL "https://github.com/taskcluster/taskcluster/releases/download/$TC_VERSION/taskcluster-proxy-darwin-amd64" -o taskcluster-proxy
chmod +x generic-worker livelog taskcluster-proxy

./generic-worker new-ed25519-keypair --file worker.key
mkdir tasks
set +e
./generic-worker run --config worker.config
case $? in
0|68)
  ;;
*)
  exit $?
  ;;
esac
