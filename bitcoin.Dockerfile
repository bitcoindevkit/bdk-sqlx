# Use the official Nix base image
FROM nixos/nix:latest

# Define build arguments with defaults
ARG NODE_USERNAME
ARG NODE_PASSWORD

# Install bitcoind and basic tools via Nix
RUN nix-channel --add https://nixos.org/channels/nixpkgs-unstable nixpkgs && \
    nix-channel --update && \
    nix-env -iA nixpkgs.bitcoind nixpkgs.coreutils

# Create data directory
RUN mkdir -p /data/bitcoin

# Expose Bitcoin RPC port and P2P port
EXPOSE 18443
EXPOSE 18444

# Set the entrypoint using shell form to enable variable interpolation
ENTRYPOINT exec /root/.nix-profile/bin/bitcoind \
    "-datadir=/data/bitcoin" \
    "-printtoconsole" \
    "-regtest=1" \
    "-server=1" \
    "-txindex=1" \
    "-rpcbind=0.0.0.0:18443" \
    "-rpcallowip=0.0.0.0/0" \
    "-rpcuser=custom_user" \
    "-rpcpassword=custom_pass" \
    "-rpcworkqueue=64" \
    "-rpcthreads=8" \
    "-fallbackfee=0.0002" \
    "-debug=1"