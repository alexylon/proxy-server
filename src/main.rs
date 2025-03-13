use axum::{
    extract::{Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use reqwest::Client;
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, error};

#[derive(Clone)]
struct AppState {
    client: Client,
}

#[derive(Deserialize)]
struct ProxyParams {
    url: String,
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create HTTP client
    let client = Client::new();
    let state = Arc::new(AppState { client });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any);

    let app = Router::new()
        .route("/proxy", any(proxy_handler))
        .route("/health", any(health_check))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 54321));
    info!("Proxy server listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn health_check() -> &'static str {
    "Proxy server is running"
}

async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ProxyParams>,
    method: Method,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, StatusCode> {
    let target_url = params.url;
    info!("Proxying request to: {} with method: {}", target_url, method);

    // Parse the URL
    let uri: Uri = target_url.parse().map_err(|e| {
        error!("Invalid URL: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    // Build the request
    let mut req_builder = state.client.request(method.clone(), uri.to_string());

    // Copy headers from the original request, except those we want to modify
    for (key, value) in headers.iter() {
        // Skip these headers - they'll be set automatically, or we'll set them manually
        if key != "host" &&
            key != "user-agent" &&
            key != "content-length" && // Skip content-length, reqwest will set it correctly
            key != "transfer-encoding" // Skip transfer-encoding too
        {
            req_builder = req_builder.header(key.as_str(), value);
        }
    }

    // Set custom headers
    req_builder = req_builder.header(
        "User-Agent",
        "Modern-Browser/1.0 (InDesign Plugin; Compatible)"
    );

    req_builder = req_builder.header(
        "X-Custom-Proxy",
        "Rust-Proxy/1.0"
    );

    // Add the body for methods that support it
    if method == Method::POST || method == Method::PUT || method == Method::PATCH {
        if !body.is_empty() {
            req_builder = req_builder.body(body);
        }
    }

    info!("Original request headers:");
    for (key, value) in headers.iter() {
        info!("  {}: {}", key, value.to_str().unwrap_or("<non-utf8 value>"));
    }

    info!("Proxied request headers:");
    if let Some(request) = req_builder.try_clone() {
        if let Ok(built_request) = request.build() {
            let headers = built_request.headers();
            for (key, value) in headers.iter() {
                info!("  {}: {}", key, value.to_str().unwrap_or("<non-utf8 value>"));
            }
        }
    }

    // Send the request
    let response = req_builder.send().await.map_err(|e| {
        error!("Request error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Build the response
    let status = response.status();
    let mut response_headers = HeaderMap::new();

    info!("Response status: {}", status);
    info!("Response headers: {:?}", response.headers());

    // Copy response headers, but skip problematic ones
    for (key, value) in response.headers().iter() {
        if key != "transfer-encoding" && key != "content-length" {
            response_headers.insert(key.clone(), value.clone());
        }
    }

    // Get response body
    let body_bytes = response.bytes().await.map_err(|e| {
        error!("Error reading response body: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // let body_string = String::from_utf8_lossy(&body_bytes);
    // info!("Response body: {}", body_string);

    // Construct the response
    let mut resp = Response::builder()
        .status(status)
        .body(axum::body::Body::from(body_bytes))
        .unwrap()
        .into_response();

    *resp.status_mut() = status;
    *resp.headers_mut() = response_headers;

    Ok(resp)
}
