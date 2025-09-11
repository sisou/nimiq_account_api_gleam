import app/web.{type Context}
import gleam/bit_array
import gleam/dynamic/decode
import gleam/float
import gleam/http.{Get, Post}
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/json
import gleam/option
import gleam/result
import jsonrpc
import nimiq/account/address.{type Address} as nimiq_address
import nimiq/coin
import nimiq/key/public_key
import nimiq/key/signature
import nimiq/transaction/network_id
import nimiq/transaction/signature_proof
import nimiq/transaction/transaction
import nimiq/transaction/transaction_builder
import wisp.{type Request, type Response}

pub fn handle_request(req: Request, ctx: Context) -> Response {
  use req <- web.middleware(req)

  case wisp.path_segments(req) {
    // This matches `/`.
    [] -> home_page(req)

    ["api", "balance"] -> balance(req, ctx)
    ["api", "send", "exchange"] -> send_exchange(req, ctx)

    ["api", "health"] -> wisp.ok() |> wisp.string_body("OK")

    // This matches all other paths.
    _ -> wisp.not_found()
  }
}

fn home_page(req: Request) -> Response {
  use <- wisp.require_method(req, Get)

  wisp.ok()
  |> wisp.html_body("Nimiq Account API")
}

fn balance(req: Request, ctx: Context) -> Response {
  use <- wisp.require_method(req, Get)

  let address =
    public_key.EdDsaPublicKey(ctx.key_pair.public)
    |> public_key.to_address()

  case fetch_balance(ctx, address) {
    Ok(balance) -> {
      wisp.ok()
      |> wisp.json_body(
        json.object([
          #(
            "address",
            address
              |> nimiq_address.to_user_friendly_address()
              |> json.string(),
          ),
          #("balance", json.int(balance)),
        ])
        |> json.to_string(),
      )
    }
    Error(err) -> {
      wisp.internal_server_error()
      |> wisp.string_body("Failed to get balance: " <> err)
    }
  }
}

fn send_exchange(req: Request, ctx: Context) -> Response {
  use <- wisp.require_method(req, Post)
  use <- validate_api_key(req, ctx.api_key)

  let address =
    public_key.EdDsaPublicKey(ctx.key_pair.public)
    |> public_key.to_address()

  let assert Ok(balance) = fetch_balance(ctx, address)

  // Only allow sending at least 1000 NIM
  use <- validate_min_balance(balance, 1000 * float.round(coin.lunas_per_coin))

  case send_transaction(ctx, ctx.exchange_address, coin.Coin(balance)) {
    Ok(tx_hash) -> {
      wisp.ok()
      |> wisp.json_body(
        json.object([
          #("hash", tx_hash |> json.string()),
          #("value", json.int(balance)),
          #(
            "recipient",
            ctx.exchange_address
              |> nimiq_address.to_user_friendly_address()
              |> json.string(),
          ),
        ])
        |> json.to_string(),
      )
    }
    Error(err) -> {
      wisp.internal_server_error()
      |> wisp.string_body("Failed to send transaction: " <> err)
    }
  }
}

fn fetch_balance(ctx: Context, address: Address) -> Result(Int, String) {
  let request =
    jsonrpc.request(method: "getAccountByAddress", id: jsonrpc.id(42))
    |> jsonrpc.request_params([
      address |> nimiq_address.to_user_friendly_address() |> json.string(),
    ])
    |> jsonrpc.request_to_json(json.preprocessed_array)
    |> json.to_string()
    |> request.set_body(make_base_request(ctx), _)

  let response =
    httpc.send(request)
    |> result.map(fn(resp) { resp.body })
    |> result.map(json.parse(
      _,
      jsonrpc.response_decoder({
        use data <- decode.subfield(["data", "balance"], decode.int)
        decode.success(data)
      }),
    ))

  unpack_rpc_response(response)
}

fn validate_api_key(
  req: Request,
  expected_api_key: String,
  next: fn() -> Response,
) -> Response {
  case req |> request.get_header("authorization") {
    Ok(provided_api_key) ->
      case provided_api_key == "Bearer " <> expected_api_key {
        True -> next()
        False -> {
          // Unauthorized
          wisp.response(401)
          |> wisp.string_body("Invalid API key")
        }
      }
    Error(Nil) ->
      // Unauthorized
      wisp.response(401)
      |> wisp.string_body("Missing API key")
  }
}

fn validate_min_balance(
  balance: Int,
  min_balance: Int,
  next: fn() -> Response,
) -> Response {
  case balance >= min_balance {
    True -> next()
    False -> {
      // Forbidden
      wisp.response(406)
      |> wisp.string_body(
        "Insufficient balance, requires at least "
        <> min_balance |> int.to_string()
        <> " luna",
      )
    }
  }
}

fn fetch_chain_height(ctx: Context) -> Result(Int, String) {
  let request =
    jsonrpc.request(method: "getBlockNumber", id: jsonrpc.id(42))
    |> jsonrpc.request_to_json(json.preprocessed_array)
    |> json.to_string()
    |> request.set_body(make_base_request(ctx), _)

  let response =
    httpc.send(request)
    |> result.map(fn(resp) { resp.body })
    |> result.map(json.parse(
      _,
      jsonrpc.response_decoder({
        use data <- decode.field("data", decode.int)
        decode.success(data)
      }),
    ))

  unpack_rpc_response(response)
}

fn send_transaction(
  ctx: Context,
  recipient: Address,
  value: coin.Coin,
) -> Result(String, String) {
  let assert Ok(validity_start_height) = fetch_chain_height(ctx)

  let tx =
    transaction_builder.new_basic(
      public_key.EdDsaPublicKey(ctx.key_pair.public) |> public_key.to_address(),
      recipient,
      value,
      coin.zero(),
      validity_start_height,
      network_id.TestAlbatross,
      option.None,
    )

  let tx =
    signature.create(
      ctx.key_pair.private,
      ctx.key_pair.public,
      tx |> transaction.serialize_content(),
    )
    |> signature_proof.single_sig(
      public_key.EdDsaPublicKey(ctx.key_pair.public),
      _,
    )
    |> signature_proof.serialize_to_bits()
    |> transaction.set_proof(tx, _)

  let assert Ok(hex) = transaction.to_hex(tx)

  let request =
    jsonrpc.request(method: "pushTransaction", id: jsonrpc.id(42))
    |> jsonrpc.request_params([hex |> json.string()])
    |> jsonrpc.request_to_json(json.preprocessed_array)
    |> json.to_string()
    |> request.set_body(make_base_request(ctx), _)

  let response =
    httpc.send(request)
    |> result.map(fn(resp) { resp.body })
    |> result.map(json.parse(
      _,
      jsonrpc.response_decoder({
        use data <- decode.field("data", decode.string)
        decode.success(data)
      }),
    ))

  unpack_rpc_response(response)
}

fn make_base_request(ctx: Context) -> request.Request(String) {
  let assert Ok(req) = request.from_uri(ctx.rpc_uri)
  req
  |> request.set_method(Post)
  |> request.set_header("Content-Type", "application/json")
  |> request.set_header(
    "Authorization",
    "Basic "
      <> bit_array.from_string(ctx.rpc_username <> ":" <> ctx.rpc_password)
    |> bit_array.base64_encode(True),
  )
}

fn unpack_rpc_response(
  response: Result(
    Result(jsonrpc.Response(a), json.DecodeError),
    httpc.HttpError,
  ),
) -> Result(a, String) {
  case response {
    Ok(Ok(result)) -> Ok(result.result)
    Ok(Error(err)) ->
      Error(
        "Invalid JSON-RPC response: "
        <> case err {
          json.UnexpectedEndOfInput -> "Unexpected end of input"
          json.UnexpectedByte(byte) -> "Unable to decode " <> byte
          json.UnexpectedSequence(sequence) -> "Unable to decode " <> sequence
          json.UnableToDecode(_) -> "Unable to decode for multiple reasons"
        },
      )
    Error(err) ->
      Error(
        "HTTP request failed: "
        <> case err {
          httpc.InvalidUtf8Response -> "Invalid UTF-8"
          httpc.FailedToConnect(..) -> "Failed to connect"
          httpc.ResponseTimeout -> "Response timeout"
        },
      )
  }
}
