use pem::Pem;
use renewc::renew::InstantAcme;
use renewc::{run, Config};
use tempfile::tempdir;

use renewc_test_support::TestPrinter;

#[cfg(target_os = "linux")]
#[tokio::test]
async fn haproxy_binds_port() {
    renewc_test_support::setup_color_eyre();
    renewc_test_support::setup_tracing();

    let mut port_user = renewc_test_support::port_binder::spawn("haproxy");
    let bound_port = port_user.port();

    let dir = tempdir().unwrap();
    let path = dir.path().join("haproxy.cfg");

    let ha_config = include_str!("haproxy.cfg");
    let ha_config = ha_config.replace("<PORT>", &bound_port.to_string());
    std::fs::write(&path, ha_config).unwrap();

    let mut config = Config::test(bound_port, &dir.path().join("test_cert"));
    config.diagnostics.haproxy.path = path;

    let err = run::<Pem>(&mut InstantAcme {}, &mut TestPrinter, &config, true)
        .await
        .unwrap_err();
    let test = format!("{err:?}");

    println!("{test:#?}");
    port_user.signal_done();
    assert!(
        test.contains("haproxy is forwarding port"),
        "error was: {test}"
    );
}

#[tokio::test]
async fn insufficent_permissions() {
    renewc_test_support::setup_color_eyre();
    renewc_test_support::setup_tracing();

    let dir = tempdir().unwrap();
    let config = Config::test(42, &dir.path().join("test_cert"));

    let err = run::<Pem>(&mut InstantAcme {}, &mut TestPrinter, &config, true)
        .await
        .unwrap_err();
    let test = format!("{err:?}");

    assert!(test.contains("You normally need sudo to attach to ports below 1025"));
    assert!(test.contains("port: 42"));
}

#[tokio::test]
async fn port_forward_suggestion_includes_ip() {
    renewc_test_support::setup_color_eyre();
    renewc_test_support::setup_tracing();

    let dir = tempfile::tempdir().unwrap();
    // port 1119 is assigned to a use by the IANA
    // and should not route to the current machine
    let config = Config::test(1119, &dir.path());
    let err = run::<Pem>(&mut InstantAcme {}, &mut TestPrinter, &config, true)
        .await
        .unwrap_err();

    let test = format!("{err:?}");
    assert!(
        test.contains("This machines local IP adress:"),
        "\n\n***********error was:\n\n {test}\n\n************\n"
    );
}
