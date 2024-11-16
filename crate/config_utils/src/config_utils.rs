use std::{
    env,
    fmt::Debug,
    fs::{self, File},
    io::BufReader,
    path::PathBuf,
};

use serde::{de::DeserializeOwned, Serialize};
#[cfg(target_os = "linux")]
use tracing::info;
use tracing::trace;

#[cfg(target_os = "linux")]
use crate::config_bail;
use crate::error::{result::ConfigUtilsResultHelper, ConfigUtilsError};

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
    // Check for the existence of the HOME environment variable on Linux and macOS
    if let Some(home) = env::var_os("HOME") {
        return Some(PathBuf::from(home));
    }
    // Check for the existence of the USERPROFILE environment variable on Windows
    else if let Some(profile) = env::var_os("USERPROFILE") {
        return Some(PathBuf::from(profile));
    }
    // Check for the existence of the HOMEDRIVE and HOMEPATH environment variables on Windows
    else if let (Some(hdrive), Some(hpath)) = (env::var_os("HOMEDRIVE"), env::var_os("HOMEPATH"))
    {
        return Some(PathBuf::from(hdrive).join(hpath));
    }
    // If none of the above environment variables exist, the home folder cannot be
    // determined
    None
}

/// Returns the default configuration path
///  or an error if the path cannot be determined
pub fn get_default_conf_path(default_local_path: &str) -> Result<PathBuf, ConfigUtilsError> {
    get_home_folder()
        .ok_or_else(|| {
            ConfigUtilsError::NotSupported("unable to determine the home folder".to_owned())
        })
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
    // - the `--conf` arg
    // - the environment variable corresponding to `env_var_name`
    // - default to a pre-determined path
    if let Some(conf_path) = conf {
        if !conf_path.exists() {
            return Err(ConfigUtilsError::NotSupported(format!(
                "Configuration file {conf_path:?} from CLI arg does not exist"
            )));
        }
        return Ok(conf_path);
    } else if let Ok(conf_path) = env::var(env_var_name).map(PathBuf::from) {
        // Error if the specified file does not exist
        if !conf_path.exists() {
            return Err(ConfigUtilsError::NotSupported(format!(
                "Configuration file {conf_path:?} specified in {env_var_name} environment \
                 variable does not exist"
            )));
        }
        return Ok(conf_path);
    }

    let user_conf_path = get_default_conf_path(conf_default_local_path);
    trace!("User conf path is at: {user_conf_path:?}");

    #[cfg(not(target_os = "linux"))]
    return user_conf_path;

    #[cfg(target_os = "linux")]
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
                        "Linux user conf path is at: {user_conf:?} but is empty, using \
                         {conf_default_system_path} instead"
                    );
                    return Ok(default_system_path);
                }
                info!(
                    "Linux user conf path is at: {user_conf:?} and will be initialized with a \
                     default value"
                );
            }
            Ok(user_conf)
        }
    }
}

pub trait ConfigUtils: Default {
    fn save(&self, conf_path: &PathBuf) -> Result<(), ConfigUtilsError>
    where
        Self: serde::ser::Serialize + std::fmt::Debug,
    {
        fs::write(
            conf_path,
            serde_json::to_string_pretty(&self)
                .with_context(|| format!("Unable to serialize default configuration {self:?}"))?,
        )
        .with_context(|| {
            format!("Unable to write default configuration to file {conf_path:?}\n{self:?}")
        })?;

        Ok(())
    }

    fn load(conf_path: &PathBuf) -> Result<Self, ConfigUtilsError>
    where
        Self: Sized,
        Self: Serialize,
        Self: DeserializeOwned,
        Self: Debug,
    {
        // Deserialize the configuration from the file, or create a default
        // configuration if none exists
        let conf = if conf_path.exists() {
            // Configuration file exists, read and deserialize it
            let file = File::open(conf_path)
                .with_context(|| format!("Unable to read configuration file {conf_path:?}"))?;
            serde_json::from_reader(BufReader::new(file))
                .with_context(|| format!("Error while parsing configuration file {conf_path:?}"))?
        } else {
            // Configuration file doesn't exist, create it with default values and serialize
            // it
            let parent = conf_path
                .parent()
                .with_context(|| format!("Unable to get parent directory of {conf_path:?}"))?;
            fs::create_dir_all(parent).with_context(|| {
                format!("Unable to create directory for configuration file {parent:?}")
            })?;

            let default_conf = Self::default();
            default_conf.save(conf_path)?;
            default_conf
        };

        Ok(conf)
    }
}
