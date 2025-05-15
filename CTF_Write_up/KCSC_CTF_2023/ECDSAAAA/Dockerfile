FROM openjdk:17-alpine

RUN apk add --update socat

WORKDIR /home/chall

COPY . .

RUN javac Main.java && jar cfe my-app.jar Main Main.class

EXPOSE 60124

CMD socat -T 60 -d -d TCP-LISTEN:60124,reuseaddr,fork EXEC:"java -jar my-app.jar"
