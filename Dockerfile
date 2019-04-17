FROM golang:stretch as build-stage

ADD . /app
WORKDIR /app
RUN go build -o snyk-filter

FROM debian:stretch-slim
COPY --from=build-stage /app/snyk-filter /snyk-filter
ENTRYPOINT ["/snyk-filter", "-severity", "final"]
