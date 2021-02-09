#!/usr/bin/env sh

img_tag=${1:-sgx-enclave}
unsigned_enclave_binary=Enclave.so
signed_enclave_binary=Enclave.signed.so

docker image inspect ${img_tag} >/dev/null 2>&1 \
    && echo "skipping build as image '${img_tag}' already exists" \
    || docker build -t ${img_tag} -f sgxra.Dockerfile .

mkdir -p bin
rm -rf bin/*
docker cp $(docker create --rm ${img_tag}):/usr/src/result/bin/${unsigned_enclave_binary} bin/
docker cp $(docker create --rm ${img_tag}):/usr/src/result/bin/${signed_enclave_binary} bin/

echo "\nunsigned and signed enclave builds are under bin/:"
ls bin/

#
$SGX_SDK/bin/x64/sgx_sign dump -cssfile enclave_sigstruct_raw -dumpfile /dev/null -enclave Enclave.signed.so
