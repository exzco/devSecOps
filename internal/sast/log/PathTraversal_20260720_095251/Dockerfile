FROM golang:1.20-alpine
WORKDIR /app
RUN echo 'hello world' > /tmp/foo.txt
CMD sh -c "if [ ! -f go.mod ]; then go mod init app; fi && go mod tidy && go run ."
