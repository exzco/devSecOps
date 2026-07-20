FROM golang:latest
WORKDIR /app
COPY . .
RUN if [ -f go.mod ]; then go mod tidy; else go mod init app && go mod tidy; fi && go build -o server .
EXPOSE 8080
CMD ["./server"]
