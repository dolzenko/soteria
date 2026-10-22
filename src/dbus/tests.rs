use super::*;
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{net::UnixListener, task::JoinHandle, time::timeout};
use zbus::{Connection, Proxy};

const DEADLINE: Duration = Duration::from_secs(2);
const OBJECT_PATH: &str = "/org/test/Soteria";
const INTERFACE: &str = "org.freedesktop.PolicyKit1.AuthenticationAgent";

struct Fixture {
    _server: Connection,
    proxy: Proxy<'static>,
    events: mpsc::Receiver<AuthenticationAgentEvent>,
    input: mpsc::Sender<AuthenticationUserEvent>,
}

impl Fixture {
    async fn new(config: SystemConfig) -> Self {
        let (sender, events) = mpsc::channel(32);
        let (input, receiver) = mpsc::channel(32);
        let server = zbus::conn::Builder::session()
            .unwrap()
            .serve_at(
                OBJECT_PATH,
                AuthenticationAgent::new(sender, receiver, config),
            )
            .unwrap()
            .build()
            .await
            .unwrap();
        let client = Connection::session().await.unwrap();
        let proxy = Proxy::new(
            &client,
            server.unique_name().unwrap().to_string(),
            OBJECT_PATH,
            INTERFACE,
        )
        .await
        .unwrap();
        Self {
            _server: server,
            proxy,
            events,
            input,
        }
    }

    fn begin(&self, cookie: &'static str) -> JoinHandle<zbus::Result<()>> {
        let proxy = self.proxy.clone();
        tokio::spawn(async move {
            proxy
                .call(
                    "BeginAuthentication",
                    &(
                        "org.test.action",
                        "Test authentication",
                        "",
                        HashMap::<String, String>::new(),
                        cookie,
                        Vec::<Identity<'static>>::new(),
                    ),
                )
                .await
        })
    }

    async fn event(&mut self) -> AuthenticationAgentEvent {
        timeout(DEADLINE, self.events.recv())
            .await
            .expect("UI event timed out")
            .expect("UI event channel closed")
    }

    async fn cancel(&self, cookie: &str) {
        timeout(
            DEADLINE,
            self.proxy
                .call::<_, _, ()>("CancelAuthentication", &(cookie,)),
        )
        .await
        .expect("CancelAuthentication blocked behind BeginAuthentication")
        .unwrap();
    }

    async fn password(&self, cookie: &str, username: &str, password: &str) {
        self.input
            .send(AuthenticationUserEvent::ProvidedPassword {
                cookie: cookie.to_owned(),
                username: username.to_owned(),
                password: password.to_owned(),
            })
            .await
            .unwrap();
    }

    async fn wait_until_queued(&self, cookie: &str) {
        let interface = self
            ._server
            .object_server()
            .interface::<_, AuthenticationAgent>(OBJECT_PATH)
            .await
            .unwrap();
        timeout(DEADLINE, async {
            loop {
                // Барьер нужен для отмены именно запроса, уже стоящего в очереди.
                if interface
                    .get()
                    .await
                    .cancellations
                    .lock()
                    .await
                    .contains_key(cookie)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Second request did not enter the queue");
    }
}

fn config(helper: &str, socket: &str) -> SystemConfig {
    figment::Figment::from(figment::providers::Serialized::defaults(HashMap::from([
        ("helper_path", helper),
        ("socket_path", socket),
    ])))
    .extract()
    .unwrap()
}

fn no_helper() -> SystemConfig {
    config("/not-a-polkit-helper", "/not-a-polkit-socket")
}

async fn assert_cancelled(request: JoinHandle<zbus::Result<()>>) {
    let error = timeout(DEADLINE, request)
        .await
        .expect("BeginAuthentication remained pending after cancellation")
        .unwrap()
        .unwrap_err();
    match error {
        zbus::Error::MethodError(name, _, _) => {
            assert_eq!(name.as_str(), "org.freedesktop.PolicyKit1.Error.Cancelled");
        }
        error => panic!("Unexpected cancellation error: {error}"),
    }
}

#[tokio::test]
async fn cancel_waiting_for_password_over_dbus() {
    let mut fixture = Fixture::new(no_helper()).await;
    for cookie in ["first", "second"] {
        let request = fixture.begin(cookie);
        assert!(matches!(&fixture.event().await,
            AuthenticationAgentEvent::Started { cookie: c, .. } if c == cookie));
        fixture.cancel(cookie).await;
        assert!(matches!(&fixture.event().await,
            AuthenticationAgentEvent::Canceled { cookie: c } if c == cookie));
        assert_cancelled(request).await;
    }
}

#[tokio::test]
async fn ui_cancel_still_completes_the_request() {
    let mut fixture = Fixture::new(no_helper()).await;
    let request = fixture.begin("ui-cancel");
    assert!(matches!(
        fixture.event().await,
        AuthenticationAgentEvent::Started { .. }
    ));
    fixture
        .input
        .send(AuthenticationUserEvent::Canceled {
            cookie: "ui-cancel".to_owned(),
        })
        .await
        .unwrap();
    assert_cancelled(request).await;
}

#[tokio::test]
async fn cancellation_matches_the_cookie_and_preserves_the_queue() {
    let mut fixture = Fixture::new(no_helper()).await;
    let first = fixture.begin("active");
    assert!(matches!(
        fixture.event().await,
        AuthenticationAgentEvent::Started { .. }
    ));
    let second = fixture.begin("queued-cancel");
    fixture.wait_until_queued("queued-cancel").await;
    fixture.cancel("queued-cancel").await;
    assert!(matches!(&fixture.event().await,
        AuthenticationAgentEvent::Canceled { cookie } if cookie == "queued-cancel"));
    assert_cancelled(second).await;
    assert!(!first.is_finished());

    let third = fixture.begin("queued-next");
    fixture.wait_until_queued("queued-next").await;
    fixture.cancel("active").await;
    assert!(matches!(&fixture.event().await,
        AuthenticationAgentEvent::Canceled { cookie } if cookie == "active"));
    assert!(matches!(&fixture.event().await,
        AuthenticationAgentEvent::Started { cookie, .. } if cookie == "queued-next"));
    assert_cancelled(first).await;

    fixture.cancel("active").await;
    assert!(matches!(&fixture.event().await,
        AuthenticationAgentEvent::Canceled { cookie } if cookie == "active"));
    assert!(!third.is_finished());
    fixture.cancel("queued-next").await;
    assert!(matches!(&fixture.event().await,
        AuthenticationAgentEvent::Canceled { cookie } if cookie == "queued-next"));
    assert_cancelled(third).await;
}

struct Helper {
    directory: PathBuf,
    socket: UnixListener,
}

impl Helper {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "soteria-cancel-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let helper = directory.join("helper");
        fs::write(
            &helper,
            r#"#!/usr/bin/python
import pathlib, socket, sys, time
sys.stdin.readline()
print('PAM_PROMPT_ECHO_OFF Password:', flush=True)
password = sys.stdin.readline().strip()
if sys.argv[1] == 'stall':
    peer = socket.socket(socket.AF_UNIX)
    peer.connect(str(pathlib.Path(__file__).parent / 'ready.sock'))
    peer.sendall(b'ready')
    time.sleep(10)
else:
    print('SUCCESS' if password == 'correct' else 'FAILURE', flush=True)
"#,
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = UnixListener::bind(directory.join("ready.sock")).unwrap();
        Self { directory, socket }
    }

    fn config(&self) -> SystemConfig {
        config(
            self.directory.join("helper").to_str().unwrap(),
            self.directory.join("absent.sock").to_str().unwrap(),
        )
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[tokio::test]
async fn cancel_during_helper_io_stops_the_helper() {
    let helper = Helper::new();
    let mut fixture = Fixture::new(helper.config()).await;
    let request = fixture.begin("helper-cancel");
    assert!(matches!(
        fixture.event().await,
        AuthenticationAgentEvent::Started { .. }
    ));
    fixture
        .password("helper-cancel", "stall", "test-password")
        .await;
    let (mut peer, _) = timeout(DEADLINE, helper.socket.accept())
        .await
        .unwrap()
        .unwrap();
    let mut ready = [0; 5];
    timeout(
        DEADLINE,
        tokio::io::AsyncReadExt::read_exact(&mut peer, &mut ready),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&ready, b"ready");

    fixture.cancel("helper-cancel").await;
    assert!(matches!(&fixture.event().await,
        AuthenticationAgentEvent::Canceled { cookie } if cookie == "helper-cancel"));
    assert_cancelled(request).await;
    let mut byte = [0];
    let read = timeout(
        DEADLINE,
        tokio::io::AsyncReadExt::read(&mut peer, &mut byte),
    )
    .await
    .expect("Cancelled helper was left running")
    .unwrap();
    assert_eq!(read, 0);
    assert!(fixture.events.try_recv().is_err());
}

#[tokio::test]
async fn helper_failure_can_be_retried_successfully() {
    let helper = Helper::new();
    let mut fixture = Fixture::new(helper.config()).await;
    let request = fixture.begin("retry");
    assert!(matches!(
        fixture.event().await,
        AuthenticationAgentEvent::Started { .. }
    ));
    fixture.password("retry", "test-user", "incorrect").await;
    assert!(matches!(&fixture.event().await,
        AuthenticationAgentEvent::AuthorizationRetry { cookie, retry_message: Some(_) }
            if cookie == "retry"));
    fixture.password("retry", "test-user", "correct").await;
    assert!(matches!(&fixture.event().await,
        AuthenticationAgentEvent::AuthorizationSucceeded { cookie } if cookie == "retry"));
    timeout(DEADLINE, request).await.unwrap().unwrap().unwrap();
}
