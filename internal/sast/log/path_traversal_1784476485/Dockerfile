FROM golang:latest AS builder
WORKDIR /app
RUN go mod init app && go get github.com/gin-gonic/gin && go mod tidy
COPY main.go .
RUN go build -o server .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/server /server
CMD ["/server"]
