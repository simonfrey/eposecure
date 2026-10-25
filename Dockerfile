FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /scanner ./cmd/scanner

# Non-root, CA certificates (nuclei template downloads, NVD) and glibc: naabu's
# packet library loads libpcap via purego, so the binary needs the dynamic loader
# even with CGO_ENABLED=0. Connect scans never actually load libpcap.
FROM gcr.io/distroless/base-debian12:nonroot@sha256:7f0c72cd138b442ae0deeb69c08b1acf5525439ba251a49ad93c320a061567e5
COPY --from=build /scanner /scanner
# nuclei templates and subfinder config live here; mount a volume to keep them between runs.
ENV HOME=/home/nonroot
VOLUME /home/nonroot
ENTRYPOINT ["/scanner"]
CMD ["serve"]
