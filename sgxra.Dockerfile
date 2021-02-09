FROM initc3/nix-sgx-sdk@sha256:9bf0a404c54cf4c41facd5135989810c38b3029a02ea01f7f331e14ca214da22

WORKDIR /usr/src
COPY . .

RUN nix-build sgxra.nix
