use std::net::TcpListener;
// Use the library crate, which is named after your package
use zk_auth_api::run;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Bind the listener here and pass it to the library
    let listener = TcpListener::bind("0.0.0.0:8080")
        .expect("Failed to bind to port 8080");
    // run() now returns a Result, so we use `?` to get the server future, then await it.
    run(listener)?.await
}
