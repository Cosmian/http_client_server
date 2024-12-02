//! Session authenticator.
//!
//! This authenticator is built on top of the `actix_identity` and `actix_session` crates
//! so it is required to have them in dependencies and setup in the application beforehand.

use actix_identity::{
    Identity, IdentityExt,
    error::{GetIdentityError, LoginError},
};
use actix_web::{
    HttpMessage, HttpRequest, HttpResponse, HttpResponseBuilder, body::BoxBody,
    error::ResponseError, http::StatusCode, http::header::ContentType,
};
use serde::{Serialize, Serializer, de::DeserializeOwned, ser::SerializeStruct};
use serde_json::Error as SerdeError;
use thiserror::Error;

use super::Authenticate;

/// The error type that can occur during an authentication by session.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Unauthenticated")]
    Unauthenticated,
    #[error("Authentication failure: {0}")]
    AuthenticationFailure(#[from] LoginError),
    #[error("Corrupted data: {0}")]
    ParseError(#[from] SerdeError),
}

impl From<GetIdentityError> for SessionError {
    fn from(_error: GetIdentityError) -> Self {
        Self::Unauthenticated
    }
}

impl Serialize for SessionError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Error", 2)?;

        state.serialize_field("error", &self.to_string())?;
        state.serialize_field("code", &self.status_code().as_u16())?;

        state.end()
    }
}

impl ResponseError for SessionError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::AuthenticationFailure(_) | Self::ParseError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let status_code = self.status_code();

        HttpResponseBuilder::new(status_code)
            .content_type(ContentType::json())
            .json(self)
    }
}

pub struct Session<T: Serialize + DeserializeOwned> {
    data: T,
    identity: Option<Identity>,
}

impl<T: Serialize + DeserializeOwned> Session<T> {
    /// Start a new session.
    ///
    /// # Arguments
    /// * `request` - The request to start the session for.
    /// * `data` -The data to attach to the session.
    ///
    /// # Errors
    /// This method can fail if:
    /// - The data cannot be serialized.
    /// - The session cannot be started.
    pub fn start(request: &HttpRequest, data: T) -> Result<Self, SessionError> {
        let identity = Identity::login(&request.extensions(), serde_json::to_string(&data)?)?;

        Ok(Self {
            data,
            identity: Some(identity),
        })
    }

    /// Stop the session forcefully.
    ///
    /// Any further requests will be unauthenticated.
    pub fn force_stop(&mut self) {
        if let Some(identity) = self.identity.take() {
            identity.logout();
        }
    }

    /// Indicate if the session is stopped.
    pub const fn is_stopped(&self) -> bool {
        self.identity.is_none()
    }

    /// Get data attached to the session.
    #[must_use]
    pub const fn data(&self) -> &T {
        &self.data
    }
}

impl<T: Serialize + DeserializeOwned> Authenticate for Session<T> {
    type Output = Self;
    type Error = SessionError;

    fn authenticate(request: &HttpRequest) -> Result<Self::Output, Self::Error> {
        request
            .get_identity()
            .map_err(Into::into)
            .and_then(|identity| {
                let data = serde_json::from_str(identity.id()?.as_str())?;

                Ok(Self {
                    data,
                    identity: Some(identity),
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::Authenticated;
    use crate::tests::session_store::MockSessionStore;

    use actix_http::Request;
    use actix_identity::IdentityMiddleware;
    use actix_session::SessionMiddleware;
    use actix_web::{
        App, HttpResponse, Responder,
        body::MessageBody,
        cookie::Key,
        dev::{Service, ServiceResponse},
        get,
        http::{Method, StatusCode},
        post, test,
    };

    #[post("/start_session")]
    async fn start_session(request: HttpRequest) -> impl Responder {
        let status_code = Session::start(&request, "user_id".to_owned())
            .map_or(StatusCode::INTERNAL_SERVER_ERROR, |_| StatusCode::OK);

        HttpResponse::new(status_code)
    }

    #[get("/session_data")]
    async fn session_data(session: Authenticated<Session<String>>) -> impl Responder {
        HttpResponse::Ok().json(session.data())
    }

    #[post("/stop_session")]
    async fn stop_session(mut session: Authenticated<Session<String>>) -> impl Responder {
        session.force_stop();

        HttpResponse::Ok()
    }

    async fn create_app()
    -> impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error>
    {
        test::init_service(
            App::new()
                .wrap(IdentityMiddleware::default())
                .wrap(SessionMiddleware::new(
                    MockSessionStore::default(),
                    Key::generate(),
                ))
                .service(start_session)
                .service(session_data)
                .service(stop_session),
        )
        .await
    }

    #[actix_web::test]
    async fn authentication_by_session() {
        let app = create_app().await;

        let request = test::TestRequest::post().uri("/start_session").to_request();
        let result = test::call_service(&app, request).await;
        assert!(result.status().is_success());

        let cookies = result.response().cookies().collect::<Vec<_>>();
        assert_eq!(cookies.len(), 1);

        #[allow(clippy::indexing_slicing)]
        let cookie = &cookies[0];

        let tests = [
            (Method::GET, "/session_data", StatusCode::OK),
            (Method::POST, "/stop_session", StatusCode::OK),
            (Method::GET, "/session_data", StatusCode::UNAUTHORIZED),
            (Method::POST, "/stop_session", StatusCode::UNAUTHORIZED),
        ];

        for (method, uri, status_code) in tests {
            let request = test::TestRequest::default()
                .method(method)
                .uri(uri)
                .cookie(cookie.clone())
                .to_request();
            let result = test::call_service(&app, request).await;
            assert_eq!(result.status(), status_code, "Failed for uri: {uri}");
        }
    }
}
