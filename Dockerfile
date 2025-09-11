FROM ghcr.io/gleam-lang/gleam:v1.12.0-elixir-alpine AS build
RUN apk add --no-cache git
RUN mix local.hex --force
COPY . /app/
RUN cd /app && gleam export erlang-shipment

FROM erlang:28-alpine
RUN \
  addgroup --system webapp && \
  adduser --system webapp -g webapp
USER webapp
COPY --from=build /app/build/erlang-shipment /app
WORKDIR /app
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["run"]