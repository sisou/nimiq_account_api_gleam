import app/router
import app/web
import dot_env
import envoy
import gleam/erlang/process
import gleam/int
import gleam/result
import gleam/uri
import mist
import nimiq/account/address
import nimiq/key/ed25519/private_key
import nimiq/key/ed25519/public_key as ed25519_public_key
import nimiq/key/public_key
import wisp
import wisp/wisp_mist

pub fn main() {
  dot_env.load_default()

  wisp.configure_logger()
  let secret_key_base = wisp.random_string(64)

  let assert Ok(private_key_raw) = envoy.get("PRIVATE_KEY")
    as "PRIVATE_KEY env var not set"
  let assert Ok(private) = private_key.from_string(private_key_raw)
    as "PRIVATE_KEY env var invalid"

  let public = ed25519_public_key.derive_key(private)

  let key_pair =
    web.KeyPair(
      private: private,
      public: public_key.EdDsaPublicKey(key: public),
    )

  let assert Ok(exchange_address_raw) = envoy.get("EXCHANGE_ADDRESS")
    as "EXCHANGE_ADDRESS env var not set"
  let assert Ok(exchange_address) = address.from_string(exchange_address_raw)
    as "EXCHANGE_ADDRESS env var invalid"

  let assert Ok(rpc_uri_raw) = envoy.get("RPC_URI") as "RPC_URI env var not set"
  let assert Ok(rpc_uri) = uri.parse(rpc_uri_raw) as "RPC_URI env var invalid"

  let assert Ok(rpc_username) = envoy.get("RPC_USERNAME")
    as "RPC_USERNAME env var not set"

  let assert Ok(rpc_password) = envoy.get("RPC_PASSWORD")
    as "RPC_PASSWORD env var not set"

  let context =
    web.Context(
      key_pair:,
      exchange_address:,
      rpc_uri:,
      rpc_username:,
      rpc_password:,
    )
  let handler = router.handle_request(_, context)

  let assert Ok(_) =
    wisp_mist.handler(handler, secret_key_base)
    |> mist.new()
    |> mist.bind(
      envoy.get("HOST")
      |> result.unwrap("127.0.0.1"),
    )
    |> mist.port(
      envoy.get("PORT")
      |> result.map(int.parse)
      |> result.flatten()
      |> result.unwrap(8000),
    )
    |> mist.start()

  process.sleep_forever()
}
