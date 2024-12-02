//! HTTP authentication for Actix Web.
//!
//! This module provides a set of utilities to authenticate HTTP requests through `actix-web`
//! extractors.
//! The available authenticators are:
//! - `Session`: A session-based authenticator that uses a cookie to store an identifier.
//!
//! # Examples
//! ```rust,no_run
//! use actix_web::{get, post, HttpRequest};
//! use actix_web::web::Path;
//! use cosmian_http_client::authentication::Authenticated;
//! #[cfg(feature = "session")]
//! use cosmian_http_client::authentication::session::Session;
//!
//! #[post("/login/<id>")]
//! async fn login(id: Path<String>, request: HttpRequest) -> String {
//!    // Create a session with the given identifier
//!    match Session::start(&request, id.into_inner()) {
//!       Ok(session) => format!("Logged in as {}", session.data()),
//!       Err(_) => "Failed to log in".to_string(),
//!    }
//! }
//!
//! #[get("/")]
//! async fn hello(session: Authenticated<Session<String>>) -> String {
//!     format!("Hello, {}!", session.data())
//! }

#[cfg(feature = "session")]
pub mod session;

use std::future::{ready, Ready};

use actix_web::{dev::Payload, FromRequest, HttpRequest};
use derive_more::{Deref, DerefMut};

/// The `Authenticate` trait is used to authenticate a request.
///
/// The `Output` associated type maybe be used to extract any useful information about the
/// authenticated request.
pub trait Authenticate {
    /// Any information about the authenticated request.
    type Output;
    type Error;

    /// Authenticate a request.
    ///
    /// # Errors
    /// Returns an error if the request could not be authenticated somehow.
    fn authenticate(request: &HttpRequest) -> Result<Self::Output, Self::Error>;
}

/// An extractor for an authenticated request.
#[derive(Deref, DerefMut)]
pub struct Authenticated<T: Authenticate>(T::Output);

impl<T: Authenticate> Authenticated<T> {
    /// Unwrap into the authenticator output.
    pub fn into_inner(self) -> T::Output {
        self.0
    }
}

impl<T: Authenticate> FromRequest for Authenticated<T>
where
    T::Error: Into<actix_web::Error>,
{
    type Error = T::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        match T::authenticate(req) {
            Ok(value) => ready(Ok(Self(value))),
            Err(error) => ready(Err(error)),
        }
    }
}
