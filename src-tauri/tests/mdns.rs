//! Real mDNS discovery between two instances. Ignored by default because CI runners and
//! container sandboxes usually have no multicast; run it on a real machine with:
//!
//! ```sh
//! cargo test --manifest-path src-tauri/Cargo.toml --test mdns -- --ignored --nocapture
//! ```
use henad_lib::discovery::Discovery;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[test]
#[ignore = "needs multicast on the local network"]
fn two_instances_on_one_machine_find_each_other() {
    let quiet: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
    let alpha = Discovery::start(
        "11111111-1111-1111-1111-111111111111".into(),
        "Henad alpha".into(),
        "fp-alpha".into(),
        47831,
        quiet.clone(),
    )
    .expect("alpha advertises");
    let beta = Discovery::start(
        "22222222-2222-2222-2222-222222222222".into(),
        "Henad beta".into(),
        "fp-beta".into(),
        47832,
        quiet,
    )
    .expect("beta advertises");

    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let seen_by_alpha = alpha
            .peer("22222222-2222-2222-2222-222222222222")
            .map(|peer| (peer.name.clone(), peer.port));
        let seen_by_beta = beta
            .peer("11111111-1111-1111-1111-111111111111")
            .map(|peer| (peer.name.clone(), peer.port));
        if let (Some(alpha_view), Some(beta_view)) = (seen_by_alpha, seen_by_beta) {
            assert_eq!(alpha_view.0, "Henad beta");
            assert_eq!(alpha_view.1, 47832);
            assert_eq!(beta_view.0, "Henad alpha");
            assert_eq!(beta_view.1, 47831);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no mutual discovery after 25s: alpha sees {:?}, beta sees {:?}",
            alpha.peers(),
            beta.peers()
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    // Peers must stay visible while the user pairs (the window is 120 s) — mDNS
    // announcements stop after the first burst, so a short staleness cutoff would
    // empty the list a few seconds in.
    std::thread::sleep(Duration::from_secs(45));
    assert!(
        alpha.peer("22222222-2222-2222-2222-222222222222").is_some(),
        "alpha lost sight of beta: {:?}",
        alpha.peers()
    );
    assert!(
        beta.peer("11111111-1111-1111-1111-111111111111").is_some(),
        "beta lost sight of alpha: {:?}",
        beta.peers()
    );

    alpha.shutdown();
    beta.shutdown();
}
