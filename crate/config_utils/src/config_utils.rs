use std::{
    env,
    fmt::Debug,
    fs::{self},
    path::PathBuf,
};

use serde::{Serialize, de::DeserializeOwned};
use tracing::{info, trace};

use crate::{
    config_bail,
    error::{ConfigUtilsError, result::ConfigUtilsResultHelper},
};

/// Returns the path to the current user's home folder.
///
/// On Linux and macOS, the home folder is typically located at
/// `/home/<username>` or `/Users/<username>`, respectively. On Windows, the
/// home folder is typically located at `C:\Users\<username>`. However, the
/// location of the home folder can be changed by the user or by system
/// administrators, so it's important to check for the existence of the
/// appropriate environment variables.
///
/// Returns `None` if the home folder cannot be determined.
pub fn get_home_folder() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .or_else(|| {
            let hdrive = env::var_os("HOMEDRIVE")?;
            env::var_os("HOMEPATH").map(|hpath| {
                let mut path = PathBuf::from(hdrive);
                path.push(hpath);
                path.into_os_string()
            })
        })
        .map(PathBuf::from)
}

/// Returns the default configuration path
///  or an error if the path cannot be determined
pub fn get_default_conf_path(default_local_path: &str) -> Result<PathBuf, ConfigUtilsError> {
    get_home_folder()
        .ok_or_else(|| ConfigUtilsError::NotFound("unable to determine the home folder".to_owned()))
        .map(|home| home.join(default_local_path))
}

pub fn location(
    conf: Option<PathBuf>,
    env_var_name: &str,
    conf_default_local_path: &str,
    conf_default_system_path: &str,
) -> Result<PathBuf, ConfigUtilsError> {
    trace!("Getting configuration file location");
    // Obtain the configuration file path from:
    // - the `conf` arg
    // - the environment variable corresponding to `env_var_name`
    // - default to a pre-determined path
    if let Some(conf_path) = conf {
        if !conf_path.exists() {
            return Err(ConfigUtilsError::NotFound(format!(
                "Configuration file {conf_path:?} does not exist"
            )));
        }
        return Ok(conf_path);
    } else if let Ok(conf_path) = env::var(env_var_name).map(PathBuf::from) {
        // Error if the specified file does not exist
        if !conf_path.exists() {
            return Err(ConfigUtilsError::NotFound(format!(
                "Configuration file {conf_path:?} specified in {env_var_name} environment \
                 variable does not exist"
            )));
        }
        return Ok(conf_path);
    }

    let user_conf_path = get_default_conf_path(conf_default_local_path);
    trace!("User conf path is at: {user_conf_path:?}");

    match user_conf_path {
        Err(_) => {
            // no user home, this may be the system attempting a load
            let default_system_path = PathBuf::from(conf_default_system_path);
            if default_system_path.exists() {
                info!("No active user, using configuration at {conf_default_system_path}");
                return Ok(default_system_path);
            }
            config_bail!(
                "no configuration found at {conf_default_system_path}, and no current user, \
                 bailing out"
            );
        }
        Ok(user_conf) => {
            // the user home exists, if there is no conf file, check
            // /etc/cosmian/<product>.json
            if !user_conf.exists() {
                let default_system_path = PathBuf::from(conf_default_system_path);
                if default_system_path.exists() {
                    info!(
                        "User conf path is at: {user_conf:?} but is empty, using \
                         {conf_default_system_path} instead"
                    );
                    return Ok(default_system_path);
                }
                info!(
                    "User conf path is at: {user_conf:?} and will be initialized with a default \
                     value"
                );
            }
            Ok(user_conf)
        }
    }
}

/// Supported file formats
pub enum SupportedFile {
    Toml,
    Json,
}

pub trait ConfigUtils: Default {
    fn to_toml(&self, conf_path: &str) -> Result<(), ConfigUtilsError>
    where
        Self: serde::ser::Serialize + std::fmt::Debug,
    {
        self.save(conf_path, SupportedFile::Toml)
    }

    fn to_json(&self, conf_path: &str) -> Result<(), ConfigUtilsError>
    where
        Self: serde::ser::Serialize + std::fmt::Debug,
    {
        self.save(conf_path, SupportedFile::Json)
    }

    fn save(&self, conf_path: &str, supported_file: SupportedFile) -> Result<(), ConfigUtilsError>
    where
        Self: serde::ser::Serialize + std::fmt::Debug,
    {
        trace!("Saving configuration to {conf_path:?}");
        let content = match supported_file {
            SupportedFile::Json => serde_json::to_string_pretty(&self)
                .with_context(|| format!("Unable to serialize default configuration {self:?}"))?,
            SupportedFile::Toml => toml::to_string_pretty(&self)
                .with_context(|| format!("Unable to serialize default configuration {self:?}"))?,
        };
        fs::write(conf_path, &content).with_context(|| {
            format!("Unable to write default configuration to file {conf_path:?}\n{self:?}")
        })?;

        Ok(())
    }

    fn load(conf_path: &str, json: bool) -> Result<Self, ConfigUtilsError>
    where
        Self: Sized,
        Self: Serialize,
        Self: DeserializeOwned,
        Self: Debug,
    {
        // Deserialize the configuration from the file, or create a default
        // configuration if none exists
        let conf_path_buf = PathBuf::from(conf_path);
        let conf = if conf_path_buf.exists() {
            // Configuration file exists, read and deserialize it
            let content = fs::read_to_string(conf_path)
                .with_context(|| format!("Unable to read configuration file {conf_path:?}"))?;
            trace!("Configuration file contents: {content}");
            if json {
                serde_json::from_str(&content).with_context(|| {
                    format!("Error while parsing configuration file {conf_path:?}")
                })?
            } else {
                toml::from_str(&content).with_context(|| {
                    format!("Error while parsing configuration file {conf_path:?}")
                })?
            }
        } else {
            // Configuration file doesn't exist, create it with default values and serialize
            // it
            if let Some(parent) = conf_path_buf.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("Unable to create directory for configuration file {parent:?}")
                })?;
            }

            let default_conf = Self::default();
            if json {
                default_conf.to_json(conf_path)?;
            } else {
                default_conf.to_toml(conf_path)?;
            }
            default_conf
        };

        Ok(conf)
    }

    fn from_toml(conf_path: &str) -> Result<Self, ConfigUtilsError>
    where
        Self: Sized,
        Self: Serialize,
        Self: DeserializeOwned,
        Self: Debug,
    {
        Self::load(conf_path, false)
    }

    fn from_json(conf_path: &str) -> Result<Self, ConfigUtilsError>
    where
        Self: Sized,
        Self: Serialize,
        Self: DeserializeOwned,
        Self: Debug,
    {
        Self::load(conf_path, true)
    }
}
