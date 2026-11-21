FROM ubuntu:24.04

RUN apt-get update && apt-get install -y libsqlite3-dev && rm -rf /var/lib/apt/lists/*

# Каталог, куда Hostless разрешает писать
RUN mkdir -p /data && chown -R 1000:1000 /data

WORKDIR /app
COPY server /app/server
RUN chmod +x /app/server

# Переменные окружения
ENV DB_PATH=/data/db.sqlite3
ENV PORT=8080

EXPOSE 8080
CMD ["/app/server"]