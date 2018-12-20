FROM golang:1.11 as builder
WORKDIR /go/src/github.com/fmitra/auth-gate
COPY Gopkg.* ./
COPY ./ ./
RUN make docker_dependencies
RUN make build

FROM scratch
WORKDIR /home
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /go/src/github.com/fmitra/auth-gate .
EXPOSE 8080
ENTRYPOINT ["./auth-gate"]
