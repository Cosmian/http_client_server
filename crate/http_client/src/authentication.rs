//! HTTP authentication for Actix Web.
//!
//! This module provides a set of utilities to authenticate HTTP requests through `actix-web`
//! extractors.
//! The available authenticators are:
//! - `Session`: A session-based authenticator that uses a cookie to store an identifier.
//!
//! # Examples
//! ```rust,no_run
//! # #[cfg(feature = "session")]
//! # mod doc {
//! use actix_web::{get, post, HttpRequest};
//! use actix_web::web::Path;
//! use cosmian_http_client::authentication::{Authenticated, Authenticate, session::Session};
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
//! # }
//! ```

pub mod either;
#[cfg(feature = "session")]
pub mod session;

use std::future::{Ready, ready};

use actix_web::{FromRequest, HttpRequest, dev::Payload};
use derive_more::{Deref, DerefMut};

pub use either::EitherExt;

/// The `Authenticate` trait is used to authenticate a request.
///
/// The `Output` associated type maybe be used to extract any useful information about the
/// authenticated request.
pub trait Authenticate: Sized {
    /// Any information about the authenticated request.
    type Output;
    type Error;

    /// Authenticate a request.
    ///
    /// # Errors
    /// Returns an error if the request could not be authenticated somehow.
    fn authenticate(request: &HttpRequest) -> Result<Self, Self::Error>;

    /// Extract the data from the authenticated request.
    fn data(&self) -> &Self::Output;
}

/// An extractor for an authenticated request.
#[derive(Deref, DerefMut)]
pub struct Authenticated<T: Authenticate>(T);

impl<T: Authenticate> Authenticated<T> {
    /// Unwrap into the authenticator output.
    pub fn into_inner(self) -> T {
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
