import app/web.{type Context}
import gleam/bit_array
import gleam/dynamic/decode
import gleam/http.{Get, Post}
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/json
import gleam/result
import jsonrpc
import nimiq/account/address.{type Address} as nimiq_address
import nimiq/key/public_key
import wisp.{type Request, type Response}

pub fn handle_request(req: Request, ctx: Context) -> Response {
  use req <- web.middleware(req)

  case wisp.path_segments(req) {
    // This matches `/`.
    [] -> home_page(req)

    ["api", "balance"] -> balance(req, ctx)
    ["api", "send", "exchange"] -> send_exchange(req, ctx)

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
    ctx.key_pair.public
    |> public_key.to_address()

  case fetch_balance(ctx, address) {
    Ok(balance) -> {
      wisp.ok()
      |> wisp.json_body(
        json.object([
          #(
            "address",
            json.string(
              address
              |> nimiq_address.to_user_friendly_address(),
            ),
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

  let address =
    ctx.key_pair.public
    |> public_key.to_address()

  let assert Ok(balance) = fetch_balance(ctx, address)

  wisp.ok()
  |> wisp.string_body(
    "Did NOT send "
    <> balance |> int.to_string()
    <> " luna to "
    <> ctx.exchange_address |> nimiq_address.to_user_friendly_address(),
  )
}

fn fetch_balance(ctx: Context, address: Address) -> Result(Int, String) {
  let assert Ok(base_request) = request.from_uri(ctx.rpc_uri)
  let base_request =
    base_request
    |> request.set_method(Post)
    |> request.set_header("Content-Type", "application/json")
    |> request.set_header(
      "Authorization",
      "Basic "
        <> bit_array.from_string(ctx.rpc_username <> ":" <> ctx.rpc_password)
      |> bit_array.base64_encode(True),
    )

  let request =
    jsonrpc.request(method: "getAccountByAddress", id: jsonrpc.id(42))
    |> jsonrpc.request_params([
      address |> nimiq_address.to_user_friendly_address() |> json.string,
    ])

  let http_request =
    request
    |> jsonrpc.request_to_json(json.preprocessed_array)
    |> json.to_string()
    |> request.set_body(base_request, _)

  let response =
    httpc.send(http_request)
    |> result.map(fn(resp) { resp.body })
    |> result.map(json.parse(
      _,
      jsonrpc.response_decoder({
        use data <- decode.subfield(["data", "balance"], decode.int)
        decode.success(data)
      }),
    ))

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
