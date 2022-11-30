#!/bin/bash

set -o pipefail
set -e 

HOOKNAME=/opt/tetragon/hook
BASEHOOKNAME=$(basename $HOOKNAME)

# minikube start --container-runtime=containerd --driver=qemu2

go build  -o $BASEHOOKNAME ./tetragon-oci-hook

mapfile -d '' JQCMD << EOF
. += { "hooks": {
	"createRuntime": [{"path": "$HOOKNAME", "args": ["$BASEHOOKNAME", "createRuntime"] }],
	"createContainer": [{"path": "$HOOKNAME", "args": ["$BASEHOOKNAME", "createContainer"] }],
}}
EOF

xdir=$(mktemp -d minikube-containerd-hook-XXXXXX)
echo $xdir

set -x
minikube ssh -- sudo mkdir -p /opt/tetragon
minikube cp $BASEHOOKNAME $HOOKNAME
minikube ssh -- sudo chmod +x $HOOKNAME

minikube ssh ctr oci spec | jq "$JQCMD" > $xdir/base-spec.json
minikube cp $xdir/base-spec.json /etc/containerd/base-spec.json
minikube ssh cat /etc/containerd/config.toml > $xdir/config.old.toml
go run patch-containerd-conf.go --config-file $xdir/config.old.toml --output $xdir/config.toml
minikube cp $xdir/config.toml /etc/containerd/config.toml
