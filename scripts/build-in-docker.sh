#!/bin/sh
set -o errexit

DEST="pkg/linux_amd64"
NAME="nomad-driver-lxd"
mkdir -p "${DEST}"

echo "===> Building lxc driver binary"
echo

docker run -it --rm \
	-w /go/src/github.com/yalh76/nomad-driver-lxd \
	-v "$(pwd):/go/src/github.com/yalh76/nomad-driver-lxd" \
       	golang:1.11 \
	/bin/sh \
	-c "apt-get update; apt-get install -y lxc-dev && go build -o ${DEST}/${NAME} ."

echo
echo "===> Done: ${DEST}/${NAME}"
