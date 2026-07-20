FROM golang:alpine
WORKDIR /app
COPY main.go .
RUN go mod init app && go get -d ./... && go mod tidy && go build -o server .
CMD ["./server"]
