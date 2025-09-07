FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o terminal-sidecar .

FROM alpine:latest
RUN apk --no-cache add ca-certificates bash
WORKDIR /root/

COPY --from=builder /app/terminal-sidecar .

EXPOSE 8081

CMD ["./terminal-sidecar"]