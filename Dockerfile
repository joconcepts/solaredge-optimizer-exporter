FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod *.go ./
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /exporter .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /exporter /exporter
EXPOSE 9877
ENTRYPOINT ["/exporter"]
