FROM ubuntu:24.04

WORKDIR /app
COPY server /app/server
RUN chmod +x /app/server

EXPOSE 8080
CMD ["/app/server"]