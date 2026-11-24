# Using ewe with Wisp

At the time of writing ewe is not an official adapter option for [wisp](https://hexdocs.pm/wisp/). 
Until a future wisp release supports ewe officially you can copy the module 
below into your project as `src/[namespace]/wisp_ewe.gleam`.

It needs `wisp` and `exception` alongside ewe:

```sh
gleam add wisp exception
```

```gleam
import ewe
import exception
import gleam/http/request
import gleam/http/response
import gleam/option
import gleam/string
import wisp
import wisp/internal

const max_body_size = 8_000_000

/// Convert a Wisp request handler into a function that can be run with the Ewe
/// web server.
///
/// # Examples
///
/// ```gleam
/// pub fn main() {
///   let secret_key_base = "..."
///
///   let assert Ok(_) =
///     handle_request
///     |> wisp_ewe.handler(secret_key_base)
///     |> ewe.new(handler: _)
///     |> ewe.listening(on: 8000)
///     |> ewe.start
///
///   process.sleep_forever()
/// }
/// ```
///
/// The secret key base is used for signing and encryption. To be able to
/// verify and decrypt messages you will need to use the same key each time
/// your program is run. Keep this value secret! Malicious people with this
/// value will likely be able to hack your application.
///
pub fn handler(
  handler: fn(wisp.Request) -> wisp.Response,
  secret_key_base: String,
) -> fn(request.Request(ewe.Connection)) -> response.Response(ewe.Body) {
  fn(req: request.Request(ewe.Connection)) {
    let connection = req.body
    let wisp_req =
      internal.make_connection(ewe_body_reader(req), secret_key_base)
      |> request.set_body(req, _)

    use <- exception.defer(fn() {
      let assert Ok(_) = wisp.delete_temporary_files(wisp_req)
    })

    handler(wisp_req)
    |> ewe_response(connection)
  }
}

fn ewe_body_reader(req: request.Request(ewe.Connection)) -> internal.Reader {
  fn(size) {
    case ewe.read_body_chunk(req, max_chunk_bytes: size, limit: max_body_size) {
      Ok(ewe.Chunk(data:, request:)) ->
        Ok(internal.Chunk(data, ewe_body_reader(request)))
      Ok(ewe.Done(..)) -> Ok(internal.ReadingFinished)
      Error(_) -> Error(Nil)
    }
  }
}

fn ewe_response(
  resp: response.Response(wisp.Body),
  connection: ewe.Connection,
) -> response.Response(ewe.Body) {
  case resp.body {
    wisp.Text(text) -> response.set_body(resp, ewe.Text(text))
    wisp.Bytes(bytes) -> response.set_body(resp, ewe.Bytes(bytes))
    wisp.File(path:, offset:, limit:) ->
      ewe_send_file(resp, connection, path, offset, limit)
  }
}

fn ewe_send_file(
  resp: response.Response(wisp.Body),
  connection: ewe.Connection,
  path: String,
  offset: Int,
  limit: option.Option(Int),
) -> response.Response(ewe.Body) {
  case ewe.file(connection, path, offset: option.Some(offset), limit:) {
    Ok(file) -> response.set_body(resp, file)
    Error(error) -> {
      string.inspect(error)
      |> wisp.log_error

      response.new(500) |> response.set_body(ewe.Empty)
    }
  }
}
```

Here's an example that shows how to use both wisp and ewe handlers. It uses `src/[namespace]/wisp_ewe.gleam`. Copy this into your app as
`src/[namespace]/[namespace].gleam`:

```gleam

import ewe
import gleam/erlang/atom
import gleam/erlang/process
import gleam/http/request
import gleam/http/response
import gleam/otp/actor
import gleam/otp/static_supervisor as supervisor
import gleam/string
import logging
import wisp
import wisp_ewe

/// The Erlang/OTP application start callback. Starts the top supervisor and
/// hands its pid back to the application controller.
pub fn start(_type: a, _args: b) -> Result(process.Pid, actor.StartError) {
  logging.log(logging.Info, "application start called")
  logging.configure()

  // TODO: make this configurable?
  // This sets the logger to print INFO level logs, and other sensible defaults
  // for a web application.
  wisp.configure_logger()

  // TODO: inject secret from environment?
  // Here we generate a secret key, but in a real application you would want to
  // load this from somewhere so that it is not regenerated on every restart.
  let secret_key_base = wisp.random_string(64)

  case
    supervisor.new(supervisor.OneForOne)
    |> supervisor.add(
      combined_handler(secret_key_base)
      |> ewe.new(handler: _)
      |> ewe.bind(to: "0.0.0.0")
      |> ewe.listening(on: 8080)
      |> ewe.supervised,
    )
    |> supervisor.start
  {
    Ok(actor.Started(pid:, ..)) -> Ok(pid)
    Error(reason) -> Error(reason)
  }
}

/// The Erlang/OTP application stop callback, called once every process in the
/// tree is down. Any final clean up goes here.
pub fn stop(_state: a) -> atom.Atom {
  logging.log(logging.Info, "application stop called")
  atom.create("ok")
}

/// The application is already running by the time this is called, so all main
/// has left to do is keep the node alive.
pub fn main() {
  logging.log(logging.Info, "application main called")
  process.sleep_forever()
}

/// The middleware stack that the request handler uses. The stack is itself a
/// middleware function!
///
/// Middleware wrap each other, so the request travels through the stack from
/// top to bottom until it reaches the request handler, at which point the
/// response travels back up through the stack.
/// 
/// The middleware used here are the ones that are suitable for use in your
/// typical web application.
///
fn wisp_middleware(
  req: wisp.Request,
  handle_request: fn(wisp.Request) -> wisp.Response,
) -> wisp.Response {
  // Permit browsers to simulate methods other than GET and POST using the
  // `_method` query parameter.
  let req = wisp.method_override(req)

  // Log information about the request and response.
  use <- wisp.log_request(req)

  // Return a default 500 response if the request handler crashes.
  use <- wisp.rescue_crashes

  // Rewrite HEAD requests to GET requests and return an empty body.
  use req <- wisp.handle_head(req)

  // Known-header based CSRF protection for non-HEAD/GET requests
  use req <- wisp.csrf_known_header_protection(req)

  // Handle the request!
  handle_request(req)
}

/// handle wisp requests
fn wisp_handle_api_requests(
  request: request.Request(wisp.Connection),
) -> response.Response(wisp.Body) {
  logging.log(logging.Info, "wisp_handle_api_requests called")
  // Apply the middleware stack for this request/response.
  use _req <- wisp_middleware(request)

  // Later we'll use templates, but for now a string will do.
  let body = "<h1>Hello, Joe! (wisp + ewe)</h1>"

  // Return a 200 OK response with the body and a HTML content type.
  wisp.html_response(body, 200)
}

/// handle ewe requests
fn ewe_handle_request(
  _request: request.Request(ewe.Connection),
) -> response.Response(ewe.Body) {
  logging.log(logging.Info, "ewe_handle_request called")
  // Give every body a `content-type`. ewe writes `content-length` and
  // `transfer-encoding` itself, ypu don't need to specify those headers.
  response.new(200)
  |> response.set_header("content-type", "text/plain; charset=utf-8")
  |> response.set_body(ewe.Text("Hello, World!"))
}

fn combined_handler(
  secret_key_base: String,
) -> fn(request.Request(ewe.Connection)) -> response.Response(ewe.Body) {
  fn(req: request.Request(ewe.Connection)) {
    logging.log(logging.Info, "combined_handler called, req.path=" <> req.path)
    let path_segments = req |> request.path_segments
    case path_segments {
      // forward specific paths to the wisp handler
      ["api"] ->
        wisp_ewe.create_handler(wisp_handle_api_requests, secret_key_base)(req)
      // forward all remaining requests to ewe
      _ -> ewe_handle_request(req)
    }
  }
}

```
