FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY main.go .
RUN go mod init app && go get -d ./... && go mod tidy && go build -o server .
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/server .
EXPOSE 8080
CMD ["./server"]
