use async_trait::async_trait;
use axum::extract::{rejection::FormRejection, FromRequest, Request};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

pub struct Form<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for Form<T>
where
    axum::Form<T>: FromRequest<S, Rejection = FormRejection>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<Value>);

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();

        let request = Request::from_parts(parts, body);

        match axum::Form::<T>::from_request(request, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => {
                let err_payload = json!({
                    "error": rejection.body_text()
                });

                Err((StatusCode::BAD_REQUEST, Json(err_payload)))
            }
        }
    }
}
