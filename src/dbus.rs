use gettextrs::gettext;
use std::{collections::HashMap, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    process,
    sync::{Mutex, mpsc, oneshot},
};
use zbus::{interface, zvariant::Value};

use crate::{
    authority::{Identity, PolkitError, Result},
    config::SystemConfig,
    events::{AuthenticationAgentEvent, AuthenticationUserEvent},
};

#[derive(Debug)]
pub struct AuthenticationAgent {
    config: SystemConfig,
    sender: mpsc::Sender<AuthenticationAgentEvent>,
    receiver: Mutex<mpsc::Receiver<AuthenticationUserEvent>>,
    cancellations: Mutex<HashMap<String, oneshot::Sender<()>>>,
}

impl AuthenticationAgent {
    pub fn new(
        sender: mpsc::Sender<AuthenticationAgentEvent>,
        receiver: mpsc::Receiver<AuthenticationUserEvent>,
        config: SystemConfig,
    ) -> Self {
        Self {
            sender,
            receiver: Mutex::new(receiver),
            cancellations: Mutex::new(HashMap::new()),
            config,
        }
    }

    async fn authenticate(
        &self,
        message: &str,
        cookie: &str,
        identities: Vec<Identity<'_>>,
    ) -> Result<()> {
        // Сериализуем только диалоги; D-Bus отмена не берёт этот lock.
        let mut receiver = self.receiver.lock().await;
        let mut names: Vec<String> = Vec::new();
        for identity in identities.iter() {
            let details = identity.get_details();
            if identity.get_kind() == "unix-user" {
                let Value::U32(uid) = details["uid"] else {
                    continue;
                };
                if let Ok(Some(u)) = etc_passwd::Passwd::from_uid(uid) {
                    if let Ok(n) = u.name.into_string() {
                        names.push(n);
                    }
                }
            }
        }

        self.sender
            .send(AuthenticationAgentEvent::Started {
                cookie: cookie.to_string(),
                message: message.to_string(),
                names,
            })
            .await
            .map_err(|_| PolkitError::Failed("Failed to send data.".to_string()))?;

        loop {
            match &receiver.recv().await.ok_or_else(|| {
                PolkitError::Failed("Failed to receive data. channel closed".to_string())
            })? {
                AuthenticationUserEvent::Canceled { cookie: c } => {
                    if c == cookie {
                        return Err(PolkitError::Cancelled(
                            "User cancelled the authentication.".to_string(),
                        ));
                    }
                }
                AuthenticationUserEvent::ProvidedPassword {
                    cookie: c,
                    username: user,
                    password: pw,
                } => {
                    if c == cookie {
                        let mut stream = UnixStream::connect(self.config.get_socket_path()).await;

                        let mut child;
                        let (reader, mut writer): (
                            BufReader<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
                            Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                        ) = if let Ok(stream) = &mut stream {
                            let (read_half, mut write_half) = stream.split();

                            write_half.write_all(user.as_bytes()).await?;
                            write_half.write_all(b"\n").await?;
                            write_half.write_all(cookie.as_bytes()).await?;
                            write_half.write_all(b"\n").await?;

                            (BufReader::new(Box::new(read_half)), Box::new(write_half))
                        } else {
                            child = process::Command::new(self.config.get_helper_path())
                                .arg(user)
                                .env("LC_ALL", "C")
                                .stdin(Stdio::piped())
                                .stdout(Stdio::piped())
                                .kill_on_drop(true)
                                .spawn()
                                .map_err(|_| {
                                    PolkitError::Failed(
                                        "Failed to the spawn polkit authentication helper."
                                            .to_string(),
                                    )
                                })?;

                            let mut stdin = child.stdin.take().ok_or(PolkitError::Failed(
                                "Child did not have stdin.".to_string(),
                            ))?;
                            let stdout = child.stdout.take().ok_or(PolkitError::Failed(
                                "Child did not have stdout.".to_string(),
                            ))?;

                            stdin.write_all(cookie.as_bytes()).await?;
                            stdin.write_all(b"\n").await?;

                            (BufReader::new(Box::new(stdout)), Box::new(stdin))
                        };

                        let mut last_info: Option<String> = None;

                        let mut lines = reader.lines();
                        while let Some(line) = lines.next_line().await? {
                            tracing::debug!("helper stdout: {}", line);
                            if let Some(sliced) = line.strip_prefix("PAM_PROMPT_ECHO_OFF") {
                                tracing::debug!("received request from helper: '{}'", sliced);
                                if sliced.trim() == "Password:" {
                                    tracing::debug!("helper replied with request for password");
                                    writer.write_all(pw.as_bytes()).await?;
                                    writer.write_all(b"\n").await?;
                                }
                            } else if let Some(info) = line.strip_prefix("PAM_TEXT_INFO") {
                                let msg = info.trim().to_string();
                                tracing::debug!("helper replied with info: {}", msg);

                                if msg.contains("minute") && msg.contains("unlock") {
                                    last_info = Some(msg.clone());
                                    self.sender
                                        .send(AuthenticationAgentEvent::AuthorizationRetry {
                                            cookie: cookie.to_string(),
                                            retry_message: Some(msg),
                                        })
                                        .await
                                        .unwrap();
                                }
                            } else if line.starts_with("FAILURE") {
                                tracing::debug!("helper replied with failure.");

                                let retry_msg = last_info.clone().unwrap_or_else(|| {
                                    gettext("Authentication failed. Please try again.")
                                });
                                self.sender
                                    .send(AuthenticationAgentEvent::AuthorizationRetry {
                                        cookie: cookie.to_string(),
                                        retry_message: Some(retry_msg),
                                    })
                                    .await
                                    .unwrap();
                                continue;
                            } else if line.starts_with("SUCCESS") {
                                tracing::debug!("helper replied with success.");

                                self.sender
                                    .send(AuthenticationAgentEvent::AuthorizationSucceeded {
                                        cookie: cookie.to_string(),
                                    })
                                    .await
                                    .unwrap();
                                return Ok(());
                            }
                        }
                        writer.flush().await?;
                    }
                }
            }
        }
    }
}

#[interface(name = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
impl AuthenticationAgent {
    async fn cancel_authentication(&self, cookie: &str) -> Result<()> {
        tracing::debug!("received request to cancel authentication for {}", cookie);
        // Закрытие старого диалога должно попасть в UI раньше запуска следующего.
        let notification = self
            .sender
            .send(AuthenticationAgentEvent::Canceled {
                cookie: cookie.to_owned(),
            })
            .await;
        if let Some(cancel) = self.cancellations.lock().await.remove(cookie) {
            if cancel.send(()).is_err() {
                tracing::debug!("authentication already finished before cancellation");
            }
        }
        notification.map_err(|_| PolkitError::Failed("Failed to send data.".to_string()))
    }

    async fn begin_authentication(
        &self,
        action_id: &str,
        message: &str,
        icon_name: &str,
        details: HashMap<String, String>,
        cookie: &str,
        identities: Vec<Identity<'_>>,
    ) -> Result<()> {
        tracing::info!("received request to authenticate");
        tracing::debug!(action_id = action_id, message = message, icon_name = icon_name, details = ?details, cookie = cookie, identities = ?identities);

        let (cancel, cancelled) = oneshot::channel();
        self.cancellations
            .lock()
            .await
            .insert(cookie.to_owned(), cancel);
        let result = tokio::select! {
            biased;
            _ = cancelled => Err(PolkitError::Cancelled("Authentication was cancelled.".to_string())),
            result = self.authenticate(message, cookie, identities) => result,
        };
        self.cancellations.lock().await.remove(cookie);
        result
    }
}

#[cfg(test)]
mod tests;
