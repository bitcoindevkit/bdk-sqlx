# Use the official Nix base image
FROM nixos/nix:latest

# Add the unstable channel
RUN nix-channel --add https://nixos.org/channels/nixpkgs-unstable nixpkgs && \
    nix-channel --update

# Install electrs from Nixpkgs
RUN nix-env -iA nixpkgs.electrs

# Create data directory for electrs
RUN mkdir -p /data/electrs/

# Expose electrs RPC port (default: 50001)
EXPOSE 50001

COPY electrs.toml /etc/electrs/config.toml

# Command to run electrs with direct auth parameters
CMD ["/root/.nix-profile/bin/electrs", "--conf=/etc/electrs/config.toml"]