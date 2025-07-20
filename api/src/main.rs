use axum::{Router, extract::State, routing::get};
use sqlx::{Pool, Postgres, postgres::PgPoolOptions};
use tokio;

#[derive(Clone)]
struct ApiState {
    pool: Pool<Postgres>,
}

#[tokio::main]
async fn main() {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect("postgres://chris:bingbong@localhost/net")
        .await
        .unwrap();

    let app = Router::new()
        .route("/", get(root))
        .with_state(ApiState { pool: pool });

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root(State(state): State<ApiState>) -> String {
    let row: (String,) = sqlx::query_as("SELECT name from node limit 1")
        .fetch_one(&state.pool)
        .await
        .unwrap_or(("empty".to_string(),));

    row.0.to_string()
}
