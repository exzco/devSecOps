FROM golang:latest
WORKDIR /app
COPY main.go .
RUN go mod init app && go get -d ./... && go mod tidy && go build -o server .
RUN echo "This is a test flag file." > /tmp/flag.txt
CMD ["./server"]
