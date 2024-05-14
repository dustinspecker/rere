#!/bin/bash
set -ex

ENABLE_LINTERS="${ENABLE_LINTERS:-}"

docker run \
	--env ENABLE_LINTERS="$ENABLE_LINTERS" \
	--env GROUP_ID="$(id --group)" \
	--env MEGALINTER_CONFIG=./configs/.mega-linter.yml \
	--env USER_ID="$(id --user)" \
	--rm \
	--volume "$PWD:/tmp/lint:rw" \
	--volume megalinter-cache:/root/.cache:rw \
	oxsecurity/megalinter:v7.11.1
