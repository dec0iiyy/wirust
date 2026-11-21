//! Points a USB-connected Android device or an emulator at the proxy through `adb`.
//!
//! `setup` makes `127.0.0.1:PORT` on the device reach the computer (`adb reverse`), sets the
//! global HTTP proxy to it and copies the CA to the device's Download folder. `reset` undoes
//! the proxy and the reverse mapping. The argument vectors are built by pure functions and
//! run without a shell, so no user input is ever interpreted by one.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, bail};

/// Where the CA lands on the device.
#[must_use]
pub fn device_ca_path() -> String {
    format!("/sdcard/Download/{}-ca.crt", crate::NAME)
}

/// The `adb` arguments of `setup`: reverse the port, set the proxy, push the CA file.
#[must_use]
pub fn setup_commands(serial: Option<&str>, port: u16, ca_file: &Path) -> Vec<Vec<OsString>> {
    let tcp = format!("tcp:{port}");
    vec![
        args(serial, &["reverse", &tcp, &tcp]),
        args(
            serial,
            &[
                "shell",
                "settings",
                "put",
                "global",
                "http_proxy",
                &format!("127.0.0.1:{port}"),
            ],
        ),
        {
            let mut push = args(serial, &["push"]);
            push.push(ca_file.as_os_str().to_owned());
            push.push(device_ca_path().into());
            push
        },
    ]
}

/// The `adb` arguments of `reset`: clear the proxy, then remove the port reversal.
#[must_use]
pub fn reset_commands(serial: Option<&str>, port: u16) -> Vec<Vec<OsString>> {
    vec![
        args(
            serial,
            &["shell", "settings", "put", "global", "http_proxy", ":0"],
        ),
        args(serial, &["reverse", "--remove", &format!("tcp:{port}")]),
    ]
}

/// The reset command as a user would type it.
#[must_use]
pub fn reset_hint(serial: Option<&str>, port: u16) -> String {
    let serial = serial.map_or_else(String::new, |s| format!(" --serial {s}"));
    format!("{} android reset{serial} --port {port}", crate::NAME)
}

fn args(serial: Option<&str>, rest: &[&str]) -> Vec<OsString> {
    let mut all: Vec<OsString> = Vec::with_capacity(rest.len() + 2);
    if let Some(serial) = serial {
        all.push("-s".into());
        all.push(serial.into());
    }
    all.extend(rest.iter().map(OsString::from));
    all
}

/// Serials of the devices `adb devices` lists as ready (state `device`).
#[must_use]
pub fn parse_devices(output: &str) -> Vec<String> {
    output
        .lines()
        .skip_while(|line| !line.starts_with("List of devices"))
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            match (fields.next(), fields.next()) {
                (Some(serial), Some("device")) => Some(serial.to_owned()),
                _ => None,
            }
        })
        .collect()
}

/// Finds `adb` in `PATH`, then in `$ANDROID_HOME/platform-tools` and
/// `$ANDROID_SDK_ROOT/platform-tools`.
///
/// # Errors
///
/// Fails with install advice when none has it.
pub fn find() -> anyhow::Result<PathBuf> {
    let exe = if cfg!(windows) { "adb.exe" } else { "adb" };
    let from_path = env::var_os("PATH")
        .map(|path| env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    let from_sdk = ["ANDROID_HOME", "ANDROID_SDK_ROOT"]
        .iter()
        .filter_map(env::var_os)
        .map(|home| PathBuf::from(home).join("platform-tools"));
    from_path
        .into_iter()
        .chain(from_sdk)
        .map(|dir| dir.join(exe))
        .find(|candidate| candidate.is_file())
        .context(
            "adb not found in PATH or $ANDROID_HOME/platform-tools; install the Android SDK \
             platform-tools and put adb on PATH",
        )
}

/// A located `adb` bound to one device.
#[derive(Debug, Clone)]
pub struct Adb {
    program: PathBuf,
    serial: Option<String>,
}

impl Adb {
    /// Finds `adb` and picks the device: `serial` if given, else the only connected one.
    ///
    /// # Errors
    ///
    /// Fails when `adb` is missing, no device is ready, or several are and no serial was
    /// given.
    pub fn open(serial: Option<String>) -> anyhow::Result<Self> {
        let program = find()?;
        if serial.is_some() {
            return Ok(Self { program, serial });
        }
        let output = Command::new(&program)
            .arg("devices")
            .output()
            .with_context(|| format!("running {} devices", program.display()))?;
        let devices = parse_devices(&String::from_utf8_lossy(&output.stdout));
        match devices.as_slice() {
            [] => bail!("no Android device or emulator is ready (adb devices lists none)"),
            [_] => Ok(Self {
                program,
                serial: None,
            }),
            several => bail!(
                "several devices are connected ({}); choose one with --serial",
                several.join(", ")
            ),
        }
    }

    /// The serial chosen with `--serial`, if any.
    #[must_use]
    pub fn serial(&self) -> Option<&str> {
        self.serial.as_deref()
    }

    /// Runs each argument vector in order, stopping at the first failure.
    ///
    /// # Errors
    ///
    /// Fails when `adb` cannot start or exits unsuccessfully.
    pub fn run_all(&self, commands: &[Vec<OsString>]) -> anyhow::Result<()> {
        for args in commands {
            let shown = args
                .iter()
                .map(|a| a.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            let output = Command::new(&self.program)
                .args(args)
                .output()
                .with_context(|| format!("running adb {shown}"))?;
            if !output.status.success() {
                bail!(
                    "adb {shown} failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(commands: &[Vec<OsString>]) -> Vec<String> {
        commands
            .iter()
            .map(|args| {
                args.iter()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect()
    }

    #[test]
    fn setup_reverses_the_port_sets_the_proxy_and_pushes_the_ca() {
        let commands = setup_commands(None, 8080, Path::new("/tmp/ca.crt"));
        assert_eq!(
            strings(&commands),
            [
                "reverse tcp:8080 tcp:8080".to_owned(),
                "shell settings put global http_proxy 127.0.0.1:8080".to_owned(),
                format!("push /tmp/ca.crt /sdcard/Download/{}-ca.crt", crate::NAME),
            ]
        );
    }

    #[test]
    fn reset_clears_the_proxy_and_the_reversal() {
        assert_eq!(
            strings(&reset_commands(Some("emulator-5554"), 9090)),
            [
                "-s emulator-5554 shell settings put global http_proxy :0",
                "-s emulator-5554 reverse --remove tcp:9090",
            ]
        );
    }

    #[test]
    fn a_hostile_serial_stays_one_argument() {
        let commands = reset_commands(Some("x; rm -rf ~"), 1);
        assert_eq!(commands[0][1], OsString::from("x; rm -rf ~"));
        assert_eq!(commands[0].len(), 8);
    }

    #[test]
    fn parses_ready_devices_only() {
        let output = "* daemon started successfully\nList of devices attached\n\
                      emulator-5554\tdevice\nR58M\tunauthorized\n0123abc\tdevice product:x\n\n";
        assert_eq!(parse_devices(output), ["emulator-5554", "0123abc"]);
        assert_eq!(
            parse_devices("List of devices attached\n\n"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn the_reset_hint_is_a_runnable_command() {
        assert_eq!(
            reset_hint(Some("emulator-5554"), 8080),
            format!(
                "{} android reset --serial emulator-5554 --port 8080",
                crate::NAME
            )
        );
    }
}
