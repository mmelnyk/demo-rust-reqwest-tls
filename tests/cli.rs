use assert_cmd::Command;

#[test]
fn help_works() {
    let bin = assert_cmd::cargo::cargo_bin!("reqwest-tls-proxy-demo");
    let mut cmd = Command::new(bin);
    cmd.arg("--help");
    cmd.assert().success();
}

#[test]
fn requires_both_mtls_parts() {
    let bin = assert_cmd::cargo::cargo_bin!("reqwest-tls-proxy-demo");
    let mut cmd = Command::new(bin);
    cmd.args(["https://example.com", "--client-cert", "foo.pem"]);
    cmd.assert().failure();
}
