use super::*;
use crate::{
    RuntimeConfig, RuntimeMode, discovery::InventorySource, onboarding::OnboardingService,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request},
};
use chinwag_client_discovery::*;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tempfile::TempDir;
use tower::ServiceExt;

const INTENT: (&str, &str) = ("x-chinwag-onboarding-intent", "1");
const ID: &str = "open-fixture-request-0001";

struct FixtureSource {
    snapshots: AtomicUsize,
    installations: AtomicUsize,
    fail: AtomicBool,
    bad_host: AtomicBool,
}

fn installed() -> InstalledSnapshot {
    InstalledSnapshot {
        observed_at_unix_ms: 1_793_398_000_321,
        installations: vec![Installation {
            id: "a".repeat(64),
            family: ClientFamily::GrokBot,
            kind: InstallationKind::Application,
            match_basis: catalogue::InstallationMatch::PublicBundleIdentity,
            canonical_path: "/Applications/Grok Bot.app".into(),
            observed_paths: vec!["/Applications/Grok Bot.app".into()],
            display_name: "Grok Bot".into(),
            bundle_id: Some("com.anysphere.sand".into()),
            version: Some("fixture".into()),
            executable_path: "/Applications/Grok Bot.app/Contents/MacOS/Grok Bot".into(),
            executable: ExecutableMetadata {
                device: 1,
                inode: 2,
                size: 8,
                modified_seconds: 1,
                modified_nanoseconds: 0,
                mode: 0o100755,
                format: ExecutableFormat::MachO,
            },
            metadata_fingerprint: "b".repeat(64),
        }],
        coverage: InstalledCoverage {
            installation_capacity: 128,
            ..InstalledCoverage::default()
        },
        limitations: vec![],
    }
}

impl InventorySource for FixtureSource {
    fn snapshot(
        &self,
    ) -> std::result::Result<InventorySnapshot, crate::discovery::DiscoveryFailure> {
        self.snapshots.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(crate::discovery::DiscoveryFailure::Unavailable);
        }
        let mut snapshot = crate::discovery::fixture_snapshot();
        if self.bad_host.load(Ordering::SeqCst) {
            snapshot.host.boot_uuid.clear();
        }
        Ok(snapshot)
    }
    fn installed(&self) -> Option<InstalledSnapshot> {
        self.installations.fetch_add(1, Ordering::SeqCst);
        Some(installed())
    }
}

struct Fixture {
    _directory: TempDir,
    app: Router,
    service: Option<Arc<OnboardingService>>,
    source: Arc<FixtureSource>,
}

impl Fixture {
    fn new(enabled: bool) -> Self {
        let directory = TempDir::new().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let service = enabled.then(|| {
            Arc::new(OnboardingService::new_fixture(&root.join("opening-journal")).unwrap())
        });
        let source = Arc::new(FixtureSource {
            snapshots: AtomicUsize::new(0),
            installations: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
            bad_host: AtomicBool::new(false),
        });
        let app = super::super::router_with_components(
            RuntimeConfig {
                bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 44339)),
                mode: RuntimeMode::Isolated {
                    data_dir: root.join("bus"),
                },
            },
            source.clone(),
            service.clone(),
        )
        .unwrap();
        Self {
            _directory: directory,
            app,
            service,
            source,
        }
    }
    async fn request(
        &self,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: String,
    ) -> (StatusCode, serde_json::Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "127.0.0.1:44339");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 20_000).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({})),
        )
    }
    async fn status(&self) -> serde_json::Value {
        let (code, value) = self
            .request(
                Method::GET,
                "/api/onboarding/status",
                &[INTENT],
                String::new(),
            )
            .await;
        assert_eq!(code, StatusCode::OK);
        value
    }
    async fn discover(&self) -> (StatusCode, serde_json::Value) {
        self.request(
            Method::GET,
            "/api/bus/clients",
            &[("x-chinwag-discovery-intent", "1")],
            String::new(),
        )
        .await
    }
    fn no_scan(&self) {
        assert_eq!(self.source.snapshots.load(Ordering::SeqCst), 0);
        assert_eq!(self.source.installations.load(Ordering::SeqCst), 0);
    }
}

fn open_body(id: &str) -> String {
    json!({"installation_id":id}).to_string()
}
fn post_headers() -> [(&'static str, &'static str); 3] {
    [
        INTENT,
        ("content-type", "application/json"),
        ("x-chinwag-request-id", ID),
    ]
}

#[tokio::test]
async fn default_runtime_exposes_disabled_capability_and_never_opens() {
    let fixture = Fixture::new(false);
    let value = fixture.status().await;
    assert_eq!(
        value,
        json!({"schema":"chinwag-native-onboarding/v1","native_open_allowed":false,"openable_installation_ids":[]})
    );
    for (method, path, headers, body) in [
        (
            Method::POST,
            "/api/onboarding/open".to_owned(),
            post_headers().to_vec(),
            open_body(&"a".repeat(64)),
        ),
        (
            Method::GET,
            format!("/api/onboarding/opens/{ID}"),
            vec![INTENT],
            String::new(),
        ),
    ] {
        assert_eq!(
            fixture.request(method, &path, &headers, body).await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    fixture.no_scan();
}

#[tokio::test]
async fn onboarding_methods_queries_and_missing_native_intent_reject_without_work() {
    let fixture = Fixture::new(true);
    for (path, allowed) in [
        ("/api/onboarding/status", Method::GET),
        ("/api/onboarding/open", Method::POST),
        (
            "/api/onboarding/opens/open-fixture-request-0001",
            Method::GET,
        ),
    ] {
        for method in [
            Method::GET,
            Method::POST,
            Method::HEAD,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ] {
            if method == allowed {
                continue;
            }
            assert_eq!(
                fixture
                    .request(method, path, &post_headers(), open_body(&"a".repeat(64)))
                    .await
                    .0,
                StatusCode::METHOD_NOT_ALLOWED
            );
        }
        assert_eq!(
            fixture
                .request(
                    allowed.clone(),
                    &format!("{path}?extra=1"),
                    &post_headers(),
                    open_body(&"a".repeat(64))
                )
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        for headers in [
            vec![],
            vec![("x-chinwag-onboarding-intent", "0")],
            vec![INTENT, INTENT],
            vec![INTENT, ("origin", "https://example.test")],
            vec![INTENT, ("host", "example.test")],
        ] {
            assert_eq!(
                fixture
                    .request(allowed.clone(), path, &headers, String::new())
                    .await
                    .0,
                StatusCode::FORBIDDEN
            );
        }
    }
    assert!(
        fixture
            .service
            .as_ref()
            .unwrap()
            .lookup(ID)
            .unwrap()
            .is_none()
    );
    fixture.no_scan();
}

#[tokio::test]
async fn opening_json_headers_ids_and_size_validate_before_controller() {
    let fixture = Fixture::new(true);
    let valid_body = open_body(&"a".repeat(64));
    for (headers, body) in [
        (
            vec![INTENT, ("x-chinwag-request-id", ID)],
            valid_body.clone(),
        ),
        (
            vec![
                INTENT,
                ("content-type", "text/plain"),
                ("x-chinwag-request-id", ID),
            ],
            valid_body.clone(),
        ),
        (
            vec![
                INTENT,
                ("content-type", "application/json"),
                ("content-type", "application/json"),
                ("x-chinwag-request-id", ID),
            ],
            valid_body.clone(),
        ),
        (
            vec![INTENT, ("content-type", "application/json")],
            valid_body.clone(),
        ),
        (
            vec![
                INTENT,
                ("content-type", "application/json"),
                ("x-chinwag-request-id", "short"),
            ],
            valid_body.clone(),
        ),
        (
            vec![
                INTENT,
                ("content-type", "application/json"),
                ("x-chinwag-request-id", ID),
                ("x-chinwag-request-id", ID),
            ],
            valid_body,
        ),
        (
            post_headers().to_vec(),
            json!({"installation_id":"a".repeat(64),"path":"/Applications/Chosen.app"}).to_string(),
        ),
        (post_headers().to_vec(), open_body(&"A".repeat(64))),
        (post_headers().to_vec(), " ".repeat(MAX_OPEN_BODY + 1)),
        (post_headers().to_vec(), "not json".into()),
    ] {
        assert_eq!(
            fixture
                .request(Method::POST, "/api/onboarding/open", &headers, body)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    assert!(
        fixture
            .service
            .as_ref()
            .unwrap()
            .lookup(ID)
            .unwrap()
            .is_none()
    );
    fixture.no_scan();
}

#[tokio::test]
async fn explicit_discovery_caches_same_projected_id_and_lookup_never_opens_or_rescans() {
    let fixture = Fixture::new(true);
    assert!(
        fixture.status().await["openable_installation_ids"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    fixture.no_scan();
    let (code, inventory) = fixture.discover().await;
    assert_eq!(code, StatusCode::OK);
    let observed = inventory["installations"]["apps"][0]["id"]
        .as_str()
        .unwrap();
    assert_eq!(
        fixture.status().await["openable_installation_ids"],
        json!([observed])
    );
    let lookup_path = format!("/api/onboarding/opens/{ID}");
    assert_eq!(
        fixture
            .request(Method::GET, &lookup_path, &[INTENT], String::new())
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert!(
        fixture
            .service
            .as_ref()
            .unwrap()
            .lookup(ID)
            .unwrap()
            .is_none()
    );
    let (code, receipt) = fixture
        .request(
            Method::POST,
            "/api/onboarding/open",
            &post_headers(),
            open_body(observed),
        )
        .await;
    assert_eq!(code, StatusCode::OK);
    let typed: chinwag_bus_client::NativeOpenReceipt =
        serde_json::from_value(receipt.clone()).unwrap();
    typed
        .validate_for(
            ID,
            &NativeOpenRequest {
                installation_id: observed.into(),
            },
        )
        .unwrap();
    assert_eq!(
        typed.state,
        chinwag_bus_client::NativeOpenState::OpenedOrReused
    );
    let (code, looked_up) = fixture
        .request(Method::GET, &lookup_path, &[INTENT], String::new())
        .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(looked_up, receipt);
    assert_eq!(fixture.source.snapshots.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.source.installations.load(Ordering::SeqCst), 1);
    for private in [
        "/Applications",
        "com.anysphere",
        "private-boot",
        "948123",
        "887321",
    ] {
        assert!(!receipt.to_string().contains(private));
    }
}

#[tokio::test]
async fn failed_discovery_invalidates_open_targets_without_breaking_bus() {
    let fixture = Fixture::new(true);
    assert_eq!(fixture.discover().await.0, StatusCode::OK);
    assert_eq!(
        fixture.status().await["openable_installation_ids"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    fixture.source.fail.store(true, Ordering::SeqCst);
    assert_eq!(fixture.discover().await.0, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        fixture.status().await["openable_installation_ids"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fixture
            .request(Method::GET, "/api/bus/status", &[], String::new())
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn cache_rejection_preserves_healthy_inventory_and_disables_old_targets() {
    let fixture = Fixture::new(true);
    assert_eq!(fixture.discover().await.0, StatusCode::OK);
    fixture.source.bad_host.store(true, Ordering::SeqCst);
    // Boot identity is host-local and not part of the public DTO schema; the
    // launch controller rejects it without making the public inventory unhealthy.
    assert_eq!(fixture.discover().await.0, StatusCode::OK);
    assert!(
        fixture.status().await["openable_installation_ids"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fixture
            .request(Method::GET, "/api/bus/status", &[], String::new())
            .await
            .0,
        StatusCode::OK
    );
}
