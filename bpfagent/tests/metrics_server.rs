//! Tests for the Prometheus metrics HTTP handler, using loopback TCP streams.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};

use bpfagent::metrics::handle_http_request;
use prometheus::{IntGauge, Registry};

/// Send `request` through a loopback connection handled by `handle_http_request`
/// and return the raw HTTP response.
fn serve(request: &str, registry: &Registry) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let mut client = TcpStream::connect(addr).expect("connect");
    client.write_all(request.as_bytes()).expect("write request");

    let (mut server, _) = listener.accept().expect("accept");
    handle_http_request(&mut server, registry).expect("handle request");
    server.shutdown(Shutdown::Write).expect("shutdown write");

    let mut response = String::new();
    client.read_to_string(&mut response).expect("read response");
    response
}

fn registry_with_metric() -> Registry {
    let registry = Registry::new();
    let gauge = IntGauge::new("test_metric", "a test metric").expect("create gauge");
    gauge.set(42);
    registry.register(Box::new(gauge)).expect("register gauge");
    registry
}

#[test]
fn metrics_path_returns_200_with_metrics_body() {
    let response = serve(
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
        &registry_with_metric(),
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "got: {}", response);
    assert!(response.contains("test_metric 42"), "got: {}", response);
}

#[test]
fn unknown_path_returns_404() {
    let response = serve("GET /nope HTTP/1.1\r\n\r\n", &Registry::new());
    assert!(response.starts_with("HTTP/1.1 404"), "got: {}", response);
    assert!(response.ends_with("Not Found"), "got: {}", response);
}

#[test]
fn empty_registry_still_returns_200() {
    let response = serve("GET /metrics HTTP/1.1\r\n\r\n", &Registry::new());
    assert!(response.starts_with("HTTP/1.1 200 OK"), "got: {}", response);
}
