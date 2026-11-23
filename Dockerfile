FROM ubuntu:24.04

RUN apt-get update && apt-get install -y libpq-dev ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server /app/server
RUN chmod +x /app/server

ENV PORT=8080

EXPOSE 8080
CMD ["/app/server"]