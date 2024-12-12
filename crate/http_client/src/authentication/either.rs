//! Extensions for `actix_web::Either`.
//!
//! This module provides a trait that extends `actix_web::Either` to handle `Authenticate` implementation
//! in a more convenient way.
//!
//! # Example
//! ```rust,no_run
//! # #[cfg(feature = "session")]
//! # mod doc {
//! use actix_web::{get, post, HttpRequest, Either, Error};
//! use actix_web::web::Path;
//! use cosmian_http_client::authentication::{Authenticated, Authenticate, EitherExt, session::Session};
//!
//! struct Admin;
//!
//! impl Authenticate for Admin {
//!    type Output = str;
//!    type Error = Error;
//!
//!    fn authenticate(request: &HttpRequest) -> Result<Self, Self::Error> {
//!         Ok(Self)
//!    }
//!
//!    fn data(&self) -> &Self::Output {
//!         "admin"
//!    }
//! }
//!
//! #[post("/")]
//! async fn protected_route(authentication: Either<Authenticated<Session<String>>, Authenticated<Admin>>) -> String {
//!    // it will get session data first and fallback to admin data if the session authentication fails somehow
//!    format!("{}", authentication.data())
//! }
//! # }
//! ```

use actix_web::Either;

use super::{Authenticate, Authenticated};

/// An extension trait for `actix_web::Either`.
pub trait EitherExt<T> {
    /// Returns a reference to the data of either side.
    fn data(&self) -> &T;
}

impl<L, R, T> EitherExt<T> for Either<Authenticated<L>, Authenticated<R>>
where
    L: Authenticate<Output = T>,
    R: Authenticate<Output = T>,
{
    fn data(&self) -> &T {
        match self {
            Self::Left(value) => value.data(),
            Self::Right(value) => value.data(),
        }
    }
}

#[cfg(test)]
mod tests {
    use actix_http::Request;
    use actix_web::{
        App, Either, Error, HttpRequest, HttpResponse, Responder,
        body::MessageBody,
        dev::{Service, ServiceResponse},
        error, get, test,
        web::Bytes,
    };

    use super::EitherExt;
    use crate::authentication::{Authenticate, Authenticated};

    macro_rules! impl_authenticate {
        ($($name:ident),+) => {$(
            struct $name(String);

            impl Authenticate for $name {
                type Output = String;
                type Error = Error;

                fn authenticate(request: &HttpRequest) -> Result<Self, Self::Error> {
                    let value = request
                        .headers()
                        .get(stringify!($name))
                        .ok_or(error::ErrorUnauthorized("unauthorized"))?
                        .to_str()
                        .map_err(|e| error::ErrorUnauthorized(e))?
                        .to_owned();

                     Ok(Self(value))
                }

                fn data(&self) -> &Self::Output {
                    &self.0
                }
            }
        )+};
    }

    impl_authenticate!(A, B);

    #[get("/")]
    async fn get_data(
        authentication: Either<Authenticated<A>, Authenticated<B>>,
    ) -> impl Responder {
        HttpResponse::Ok().body(authentication.data().to_string())
    }

    async fn create_app()
    -> impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error>
    {
        test::init_service(App::new().service(get_data)).await
    }

    #[actix_web::test]
    async fn either_authentication() {
        let app = create_app().await;

        let request = test::TestRequest::get()
            .uri("/")
            .insert_header(("A", "testA"))
            .to_request();

        let result = test::call_service(&app, request).await;
        assert_eq!(result.status(), 200);

        let body = test::read_body(result).await;
        assert_eq!(body, Bytes::from_static(b"testA"));

        let request = test::TestRequest::get()
            .uri("/")
            .insert_header(("B", "testB"))
            .to_request();

        let result = test::call_service(&app, request).await;
        assert!(result.status().is_success());

        let body = test::read_body(result).await;
        assert_eq!(body, Bytes::from_static(b"testB"));

        let request = test::TestRequest::get().uri("/").to_request();

        let result = test::call_service(&app, request).await;
        assert!(result.status().is_client_error());
    }
}
