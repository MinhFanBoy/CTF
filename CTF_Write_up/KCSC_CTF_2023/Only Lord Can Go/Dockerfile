FROM golang:1.18-alpine

RUN apk add socat

WORKDIR /home/chall

COPY . .
RUN go build main.go

EXPOSE 60123

CMD socat -T 30 -d -d TCP-LISTEN:60123,reuseaddr,fork EXEC:"./main"