# otrust as a container image, for running `otrust verify` (or keygen) in CI. It has no docker CLI, so
# `assess` and `verify --recheck` need the binary on a host with docker instead.
# The release workflow builds it from the released linux/amd64 binary: docker build --build-arg BIN=dist/otrust-linux-amd64 .
# distroless static: CA certificates for --online, no shell, runs as non-root
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG BIN=otrust
COPY ${BIN} /otrust
USER nonroot:nonroot
ENTRYPOINT ["/otrust"]
