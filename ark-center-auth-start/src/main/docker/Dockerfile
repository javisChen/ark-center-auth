FROM openjdk:21-oraclelinux8
WORKDIR /app
COPY ark-center-auth.jar /app
EXPOSE 8080
ENV SYS_OPT=""
ENTRYPOINT java $SYS_OPT -jar /app/ark-center-auth.jar