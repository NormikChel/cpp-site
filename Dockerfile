FROM ubuntu:24.04

RUN apt-get update && apt-get install -y libsqlite3-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server /app/server
RUN chmod +x /app/server

ENV DB_PATH=/tmp/db.sqlite3
ENV PORT=8080

EXPOSE 8080
CMD ["/app/server"]