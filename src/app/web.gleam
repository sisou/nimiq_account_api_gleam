import gleam/uri
import nimiq/account/address
import nimiq/key/ed25519/private_key
import nimiq/key/public_key
import wisp

pub type KeyPair {
  KeyPair(private: private_key.PrivateKey, public: public_key.PublicKey)
}

pub type Context {
  Context(
    rpc_uri: uri.Uri,
    rpc_username: String,
    rpc_password: String,
    key_pair: KeyPair,
    exchange_address: address.Address,
  )
}

pub fn middleware(
  req: wisp.Request,
  handle_request: fn(wisp.Request) -> wisp.Response,
) -> wisp.Response {
  let req = wisp.method_override(req)
  use <- wisp.log_request(req)
  use <- wisp.rescue_crashes()
  use req <- wisp.handle_head(req)
  use req <- wisp.csrf_known_header_protection(req)

  handle_request(req)
}
