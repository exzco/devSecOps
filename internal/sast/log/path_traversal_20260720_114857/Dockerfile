FROM golang:latest
WORKDIR /app
COPY . .
RUN go mod tidy && go build -o server .
EXPOSE 8080
CMD ["./server"]
