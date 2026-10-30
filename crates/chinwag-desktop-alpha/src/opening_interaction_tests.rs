use super::*;
use gpui_kit::{TestAppContext, test::TestWindowExt};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    thread,
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(chinwag_bus_client::new_request_id().unwrap());
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn drafts(&self) -> PathBuf {
        self.0.join("drafts.json")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn inventory() -> Value {
    let mut value = super::interaction_tests::discovery_snapshot_fixture("Studio");
    value["installations"] = json!({
        "observed_at_unix_ms":1793361786000_u64,
        "apps":[
            {"id":"a".repeat(64),"family":"grok_bot","kind":"application","running_instances":0,"state":"installed_unverified"},
            {"id":"b".repeat(64),"family":"grok_bot","kind":"application","running_instances":1,"state":"installed_unverified"}
        ],
        "coverage":{"entry_capacity":4096,"entries_examined":2,"installation_capacity":128,"capacity_reached":false,"unavailable_roots":0,"invalid_metadata":0}
    });
    value
}

fn status(allowed: bool) -> Value {
    json!({"schema":"chinwag-native-onboarding/v1","native_open_allowed":allowed,
        "openable_installation_ids":if allowed { vec!["a".repeat(64),"b".repeat(64)] } else { Vec::<String>::new() }})
}

fn header<'a>(request: &'a str, name: &str) -> &'a str {
    request
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.trim())
        })
        .unwrap()
}

fn reply(request: &str, installation_id: String, state: &str) -> Value {
    json!({"schema":"chinwag-native-open/v1","request_id":header(request,"X-Chinwag-Request-Id"),
        "installation_id":installation_id,"state":state,"message":"Synthetic fixture result"})
}

fn fixture(
    expected: usize,
    mut respond: impl FnMut(&str, usize) -> (u16, Value) + Send + 'static,
) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let worker = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut requests = Vec::new();
        while requests.len() < expected {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "opening fixture did not receive expected requests"
                    );
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("accept fixture: {error}"),
            };
            let mut bytes = Vec::new();
            let request = loop {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                assert!(
                    !remaining.is_zero(),
                    "opening fixture exceeded its total request bound"
                );
                stream.set_read_timeout(Some(remaining)).unwrap();
                let mut chunk = [0; 2048];
                let count = stream.read(&mut chunk).unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&chunk[..count]);
                assert!(bytes.len() < 16_384);
                if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    let text = std::str::from_utf8(&bytes[..end]).unwrap();
                    let length = text
                        .lines()
                        .find_map(|line| {
                            line.split_once(':')
                                .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                                .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break String::from_utf8(bytes).unwrap();
                    }
                }
            };
            let (code, value) = respond(&request, requests.len());
            let body = serde_json::to_vec(&value).unwrap();
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(
                !remaining.is_zero(),
                "opening fixture exceeded its total response bound"
            );
            stream.set_write_timeout(Some(remaining)).unwrap();
            write!(stream,"HTTP/1.1 {code} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
            stream.write_all(&body).unwrap();
            requests.push(request);
        }
        requests
    });
    (endpoint, worker)
}

#[gpui_kit::test]
fn exact_copy_click_posts_once_after_pending_is_saved_and_keeps_family_grouping(
    cx: &mut TestAppContext,
) {
    let directory = Directory::new();
    let drafts = directory.drafts();
    let store_path = openings::path_for_drafts(&drafts).unwrap();
    let (endpoint, worker) = fixture(3, move |request, index| match index {
        0 => {
            assert!(request.starts_with("GET /api/bus/clients "));
            (200, inventory())
        }
        1 => {
            assert!(request.starts_with("GET /api/onboarding/status "));
            (200, status(true))
        }
        _ => {
            assert!(request.starts_with("POST /api/onboarding/open "));
            assert_eq!(header(request, "X-Chinwag-Onboarding-Intent"), "1");
            let body: Value =
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(body["installation_id"], "a".repeat(64));
            let saved: Value =
                serde_json::from_slice(&std::fs::read(&store_path).unwrap()).unwrap();
            assert_eq!(saved["attempts"][0]["state"], "pending");
            assert_eq!(
                saved["attempts"][0]["id"],
                header(request, "X-Chinwag-Request-Id")
            );
            (200, reply(request, "a".repeat(64), "opened_or_reused"))
        }
    });
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| {
                Workbench::with_settings(window, cx, endpoint.clone(), Some(drafts.clone()))
            })
        })
        .unwrap()
    });
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click("find-client-apps", cx);
    })
    .unwrap();
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click(("open-installation", 0_usize), cx);
        window.click(("open-installation", 0_usize), cx);
    })
    .unwrap();
    cx.run_until_parked();
    let requests = worker.join().unwrap();
    cx.run_until_parked();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.starts_with("POST "))
            .count(),
        1
    );
    cx.update(|cx| {
        let view = view.read(cx);
        assert_eq!(view.client_inventory.rows().len(), 1);
        assert_eq!(view.client_inventory.openable_copies().len(), 2);
        let store = view.openings.as_ref().unwrap();
        assert_eq!(store.attempts.len(), 1);
        assert_eq!(
            store.attempts[0].summary(),
            "Opened/reused · connection setup pending"
        );
        assert!(matches!(view.connection, Connection::Disconnected));
        assert!(view.send_task.is_none());
    });
}

#[gpui_kit::test]
fn older_runtime_status_404_preserves_inventory_and_exposes_no_open_action(
    cx: &mut TestAppContext,
) {
    let directory = Directory::new();
    let (endpoint, worker) = fixture(2, |request, index| {
        assert!(request.starts_with("GET "));
        if index == 0 {
            (200, inventory())
        } else {
            (404, json!({"error":"older runtime"}))
        }
    });
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| {
                Workbench::with_settings(window, cx, endpoint.clone(), Some(directory.drafts()))
            })
        })
        .unwrap()
    });
    cx.update_window(window, |_, _, cx| {
        view.update(cx, |view, cx| {
            assert!(view.client_inventory.openable_copies().is_empty());
            view.open_installation(&"a".repeat(64), cx);
            view.load_client_inventory(&endpoint, view.connection_generation, cx);
        })
    })
    .unwrap();
    cx.run_until_parked();
    assert!(
        worker
            .join()
            .unwrap()
            .iter()
            .all(|request| request.starts_with("GET "))
    );
    cx.run_until_parked();
    cx.update(|cx| {
        let view = view.read(cx);
        assert!(matches!(
            view.client_inventory.state,
            InventoryState::Ready(_)
        ));
        assert!(view.client_inventory.openable_copies().is_empty());
        assert!(view.openings.as_ref().unwrap().attempts.is_empty());
    });
}

#[gpui_kit::test]
fn restored_pending_attempt_checks_original_endpoint_by_get_without_find_or_post(
    cx: &mut TestAppContext,
) {
    let directory = Directory::new();
    let (endpoint, worker) = fixture(1, |request, _| {
        assert!(request.starts_with("GET /api/onboarding/opens/"));
        let id = request
            .split_whitespace()
            .nth(1)
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap();
        (
            200,
            json!({"schema":"chinwag-native-open/v1","request_id":id,"installation_id":"a".repeat(64),"state":"opened_or_reused","message":"Synthetic restored receipt"}),
        )
    });
    let mut store =
        OpeningStore::open(openings::path_for_drafts(&directory.drafts()).unwrap()).unwrap();
    let attempt = store.prepare(&endpoint, &"a".repeat(64)).unwrap();
    drop(store);
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| {
                Workbench::with_settings(
                    window,
                    cx,
                    "http://127.0.0.1:1".into(),
                    Some(directory.drafts()),
                )
            })
        })
        .unwrap()
    });
    cx.update(|cx| {
        let view = view.read(cx);
        assert!(
            view.opening_tasks.is_empty(),
            "startup must not replay a pending POST"
        );
        assert!(view.client_inventory.openable_copies().is_empty());
        assert!(
            view.openings
                .as_ref()
                .unwrap()
                .blocks(&endpoint, &attempt.installation_id)
        );
    });
    cx.update_window(window, |_, window, cx| {
        window.draw(cx).clear(cx);
        window.click(("check-opening-status", 0_usize), cx);
    })
    .unwrap();
    cx.run_until_parked();
    let requests = worker.join().unwrap();
    cx.run_until_parked();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET "));
    cx.update(|cx| {
        assert_eq!(
            view.read(cx).openings.as_ref().unwrap().attempts[0].summary(),
            "Opened/reused · connection setup pending"
        )
    });
}

#[gpui_kit::test]
fn malformed_open_receipt_stays_uncertain_while_another_copy_can_open(cx: &mut TestAppContext) {
    let directory = Directory::new();
    let (endpoint, worker) = fixture(4, |request, index| match index {
        0 => (200, inventory()),
        1 => (200, status(true)),
        _ => {
            assert!(request.starts_with("POST /api/onboarding/open "));
            let body: Value =
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
            let selected = body["installation_id"].as_str().unwrap();
            (
                200,
                reply(
                    request,
                    if selected == "a".repeat(64) {
                        "f".repeat(64)
                    } else {
                        selected.into()
                    },
                    "opened_or_reused",
                ),
            )
        }
    });
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| {
                Workbench::with_settings(window, cx, endpoint.clone(), Some(directory.drafts()))
            })
        })
        .unwrap()
    });
    cx.update_window(window, |_, _, cx| {
        view.update(cx, |view, cx| {
            view.load_client_inventory(&endpoint, view.connection_generation, cx)
        })
    })
    .unwrap();
    cx.run_until_parked();
    cx.update_window(window, |_, _, cx| {
        view.update(cx, |view, cx| {
            view.open_installation(&"a".repeat(64), cx);
            view.open_installation(&"a".repeat(64), cx);
            assert!(!view.can_open_installation(&"a".repeat(64), cx));
            assert!(
                !view.can_open_installation(&"b".repeat(64), cx),
                "new openings wait only while the current request is in flight"
            );
        })
    })
    .unwrap();
    cx.run_until_parked();
    cx.update_window(window, |_, _, cx| {
        view.update(cx, |view, cx| {
            assert!(view.opening_tasks.is_empty());
            assert!(!view.can_open_installation(&"a".repeat(64), cx));
            assert!(
                view.can_open_installation(&"b".repeat(64), cx),
                "an uncertain copy must not require restart before another copy can open"
            );
            view.open_installation(&"b".repeat(64), cx);
        })
    })
    .unwrap();
    cx.run_until_parked();
    assert_eq!(
        worker
            .join()
            .unwrap()
            .iter()
            .filter(|request| request.starts_with("POST "))
            .count(),
        2
    );
    cx.run_until_parked();
    cx.update(|cx| {
        let view = view.read(cx);
        let attempts = &view.openings.as_ref().unwrap().attempts;
        assert_eq!(attempts.len(), 2);
        assert!(attempts[0].unresolved());
        assert!(!attempts[0].summary().contains("Opened/reused"));
        assert_eq!(
            attempts[1].summary(),
            "Opened/reused · connection setup pending"
        );
        assert!(!view.can_open_installation(&"a".repeat(64), cx));
    });
}

#[gpui_kit::test]
fn stale_endpoint_or_attempt_completion_cannot_confirm_an_opening(cx: &mut TestAppContext) {
    let directory = Directory::new();
    let endpoint = "http://127.0.0.1:41111";
    cx.update(init);
    let (window, view) = cx.update(|cx| {
        open_window(WindowOptions::default(), cx, |window, cx| {
            cx.new(|cx| {
                Workbench::with_settings(window, cx, endpoint.into(), Some(directory.drafts()))
            })
        })
        .unwrap()
    });
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            let attempt = view
                .openings
                .as_mut()
                .unwrap()
                .prepare(endpoint, &"a".repeat(64))
                .unwrap();
            view.opening_generations.insert(attempt.id.clone(), 2);
            let mut flight = OpeningFlight {
                id: attempt.id.clone(),
                attempt_endpoint: endpoint.into(),
                view_endpoint: endpoint.into(),
                epoch: view.opening_epoch,
                generation: 1,
            };
            let receipt = NativeOpenReceipt {
                schema: "chinwag-native-open/v1".into(),
                request_id: attempt.id.clone(),
                installation_id: attempt.installation_id.clone(),
                state: chinwag_bus_client::NativeOpenState::OpenedOrReused,
                message: "Synthetic late receipt".into(),
            };
            assert!(!view.apply_opening_result(&flight, Ok(Some(receipt.clone())), cx));
            flight.generation = 2;
            view.endpoint.update(cx, |state, cx| {
                state.set_value("http://127.0.0.1:42222", window, cx)
            });
            assert!(!view.apply_opening_result(&flight, Ok(Some(receipt)), cx));
            assert_eq!(
                view.openings.as_ref().unwrap().attempts[0].state,
                openings::OpeningState::Pending
            );
        })
    })
    .unwrap();
}
