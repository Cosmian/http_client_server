use std::str::FromStr;
use std::{cell::RefCell, collections::HashMap};

use actix_session::storage::{LoadError, SaveError, SessionKey, SessionStore, UpdateError};
use actix_web::cookie::time::Duration;
use anyhow::Error;

/// A simple in-memory session store for testing purposes.
#[derive(Default)]
pub struct MockSessionStore {
    data: RefCell<Vec<HashMap<String, String>>>,
}

/// Convert a session key to an index into the data store.
fn key_to_index(session_key: &SessionKey) -> Result<usize, Error> {
    usize::from_str(session_key.as_ref()).map_err(Into::into)
}

impl SessionStore for MockSessionStore {
    async fn load(
        &self,
        session_key: &SessionKey,
    ) -> Result<Option<HashMap<String, String>>, LoadError> {
        key_to_index(session_key)
            .map(|i| self.data.borrow().get(i).cloned())
            .map_err(LoadError::Deserialization)
    }

    async fn save(
        &self,
        session_state: HashMap<String, String>,
        _ttl: &Duration,
    ) -> Result<SessionKey, SaveError> {
        let key = SessionKey::try_from(self.data.borrow().len().to_string())
            .map_err(Error::from)
            .map_err(SaveError::Serialization)?;

        self.data.borrow_mut().push(session_state);

        Ok(key)
    }

    async fn update(
        &self,
        session_key: SessionKey,
        session_state: HashMap<String, String>,
        _ttl: &Duration,
    ) -> Result<SessionKey, UpdateError> {
        key_to_index(&session_key)
            .map_err(UpdateError::Other)
            .and_then(|i| match self.data.borrow_mut().get_mut(i) {
                Some(data) => {
                    *data = session_state;

                    Ok(session_key)
                }
                None => Err(UpdateError::Other(Error::msg("No such key"))),
            })
    }

    async fn update_ttl(&self, _session_key: &SessionKey, _ttl: &Duration) -> Result<(), Error> {
        unimplemented!();
    }

    async fn delete(&self, session_key: &SessionKey) -> Result<(), Error> {
        match key_to_index(session_key)? {
            i if i < self.data.borrow().len() => {
                self.data.borrow_mut().remove(i);

                Ok(())
            }
            _ => Err(Error::msg("No such key")),
        }
    }
}
