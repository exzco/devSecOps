FROM golang:latest
WORKDIR /app
COPY main.go .
RUN echo "Normal file content" > /tmp/hello.txt
RUN go mod init app && go get -d ./... && go mod tidy && go build -o server .
EXPOSE 8080
CMD ["./server"]
