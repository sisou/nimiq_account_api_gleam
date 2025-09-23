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
    ["api", "send", "exchange", amount] -> send_to_exchange(req, ctx, amount)
    ["api", "send", address, amount] ->
      send_to_address(req, ctx, address, amount)
    ["api", "transaction", hash] -> get_transaction(req, ctx, hash)

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

fn send_to_exchange(
  req: Request,
  ctx: Context,
  amount_param: String,
) -> Response {
  use <- wisp.require_method(req, Post)
  use <- validate_api_key(req, ctx.api_key)
  use amount <- parse_amount(amount_param)

  // Only allow sending at least 10000 NIM
  use <- validate_min_amount(amount, 10_000 * float.round(coin.lunas_per_coin))

  let address =
    public_key.EdDsaPublicKey(ctx.key_pair.public)
    |> public_key.to_address()

  let assert Ok(balance) = fetch_balance(ctx, address)

  use <- validate_amount_vs_balance(amount, balance)

  case send_transaction(ctx, ctx.exchange_address, coin.Coin(amount)) {
    Ok(tx_hash) -> {
      wisp.ok()
      |> wisp.json_body(
        json.object([
          #("hash", tx_hash |> json.string()),
          #("value", amount |> json.int()),
          #(
            "recipient",
            ctx.exchange_address
              |> nimiq_address.to_user_friendly_address()
              |> json.string(),
          ),
          #("status", "PENDING" |> json.string()),
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

fn send_to_address(
  req: Request,
  ctx: Context,
  recipient_param: String,
  amount_param: String,
) -> Response {
  use <- wisp.require_method(req, Post)
  use <- validate_api_key(req, ctx.api_key)
  use recipient <- parse_address(recipient_param)
  use amount <- parse_amount(amount_param)

  // TODO: This method should ideally not allow sending to just any recipient. It should instead only allow returning
  // funds to addresses that also sent funds in. It must then however track in persisted state which transactions have
  // been refunded that way.

  let address =
    public_key.EdDsaPublicKey(ctx.key_pair.public)
    |> public_key.to_address()

  let assert Ok(balance) = fetch_balance(ctx, address)

  use <- validate_amount_vs_balance(amount, balance)

  case send_transaction(ctx, recipient, coin.Coin(amount)) {
    Ok(tx_hash) -> {
      wisp.ok()
      |> wisp.json_body(
        json.object([
          #("hash", tx_hash |> json.string()),
          #("value", amount |> json.int()),
          #(
            "recipient",
            recipient
              |> nimiq_address.to_user_friendly_address()
              |> json.string(),
          ),
          #("status", "PENDING" |> json.string()),
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

fn get_transaction(req: Request, ctx: Context, hash: String) -> Response {
  use <- wisp.require_method(req, Get)
  use <- validate_api_key(req, ctx.api_key)

  let assert Ok(current_height) = fetch_chain_height(ctx)

  case fetch_transaction(ctx, hash, current_height) {
    Ok(tx) -> {
      wisp.ok()
      |> wisp.json_body(
        json.object([
          #("hash", tx.hash |> json.string()),
          #("value", tx.value |> json.int()),
          #("recipient", tx.recipient |> json.string()),
          #("status", tx.status |> json.string()),
        ])
        |> json.to_string(),
      )
    }
    Error(err) -> {
      wisp.internal_server_error()
      |> wisp.string_body("Failed to get transaction: " <> err)
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

fn parse_amount(amount_str: String, next: fn(Int) -> Response) -> Response {
  case amount_str |> int.parse() {
    Ok(amount) -> next(amount)
    Error(Nil) ->
      // Not Acceptable
      wisp.response(406)
      |> wisp.string_body("Invalid amount: " <> amount_str)
  }
}

fn parse_address(address_str: String, next: fn(Address) -> Response) -> Response {
  case address_str |> nimiq_address.from_string() {
    Ok(address) -> next(address)
    Error(err) ->
      // Not Acceptable
      wisp.response(406)
      |> wisp.string_body(
        "Invalid address: " <> address_str <> " (" <> err <> ")",
      )
  }
}

fn validate_min_amount(
  amount amount: Int,
  min_amount min_amount: Int,
  next next: fn() -> Response,
) -> Response {
  case amount >= min_amount {
    True -> next()
    False -> {
      // Forbidden
      wisp.response(406)
      |> wisp.string_body(
        "Insufficient amount, requires at least "
        <> min_amount |> int.to_string()
        <> " luna",
      )
    }
  }
}

fn validate_amount_vs_balance(
  amount amount: Int,
  balance balance: Int,
  next next: fn() -> Response,
) -> Response {
  case amount <= balance {
    True -> next()
    False -> {
      // Forbidden
      wisp.response(406)
      |> wisp.string_body(
        "Insufficient balance, can sent at most "
        <> balance |> int.to_string()
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

type Transaction {
  Transaction(hash: String, value: Int, recipient: String, status: String)
}

fn fetch_transaction(
  ctx: Context,
  hash: String,
  current_height: Int,
) -> Result(Transaction, String) {
  let request =
    jsonrpc.request(method: "getTransactionByHash", id: jsonrpc.id(42))
    |> jsonrpc.request_params([hash |> json.string()])
    |> jsonrpc.request_to_json(json.preprocessed_array)
    |> json.to_string()
    |> request.set_body(make_base_request(ctx), _)

  let response =
    httpc.send(request)
    |> result.map(fn(resp) { resp.body })
    |> result.map(json.parse(_, jsonrpc.message_decoder()))

  unpack_rpc_message(response)
  |> result.map(fn(message) {
    case message {
      jsonrpc.ResponseMessage(jsonrpc.Response(_, _, result)) -> {
        decode.run(result, {
          use hash <- decode.subfield(["data", "hash"], decode.string)
          use value <- decode.subfield(["data", "value"], decode.int)
          use recipient <- decode.subfield(["data", "to"], decode.string)
          use block_number <- decode.subfield(
            ["data", "blockNumber"],
            decode.int,
          )
          let status = case current_height / 60 > block_number / 60 {
            True -> "CONFIRMED"
            False -> "INCLUDED"
          }
          decode.success(Transaction(hash:, value:, recipient:, status:))
        })
        |> result.replace_error("Failed to decode transaction")
      }
      jsonrpc.ErrorResponseMessage(jsonrpc.ErrorResponse(_, _, error)) ->
        Error(
          "RPC Error: " <> int.to_string(error.code) <> " - " <> error.message,
        )
      _ -> Error("Invalid RPC response")
    }
  })
  |> result.flatten()
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

fn unpack_rpc_message(
  response: Result(Result(a, json.DecodeError), httpc.HttpError),
) -> Result(a, String) {
  case response {
    Ok(Ok(message)) -> Ok(message)
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

fn unpack_rpc_response(
  response: Result(
    Result(jsonrpc.Response(a), json.DecodeError),
    httpc.HttpError,
  ),
) -> Result(a, String) {
  case unpack_rpc_message(response) {
    Ok(result) -> Ok(result.result)
    Error(err) -> Error(err)
  }
}
