//! Interop between `macula-pqc`'s TLS configurations and OTP's own `ssl`.
//!
//! Run with `scripts/otp-interop.sh`. Not part of the gate: it needs an
//! OTP installation with ML-KEM (28.4 or later), which CI does not have.
//!
//! # Why OTP
//!
//! OTP's `ssl` is the one INDEPENDENT implementation of
//! `SecP384r1MLKEM1024` there is to exchange with: no Rust provider has
//! one, so `macula-pqc-kx`'s own tests can only exchange that group with
//! itself. OTP composes the hybrid in its own Erlang code and takes ML-KEM
//! and ECDH from its `crypto` library, so a completed handshake means two
//! independently written implementations agreed on share order, lengths,
//! splitting and the combined secret. `SecP256r1MLKEM768` is checked the
//! same way, against a second independent implementation of it.
//!
//! # What each case checks
//!
//! OTP offers exactly ONE group per case, so a completed handshake leaves
//! nothing else to have agreed on, and the rustls side reports the group
//! it negotiated as well. A `ping`/`pong` then crosses the connection,
//! both roles, so the agreed keys also work for traffic.
//!
//! The negative control: OTP offering only classical groups must fail to
//! agree with `macula-pqc` in both roles. The passing cases are its
//! positive twin: the same harness, a group in common, a handshake that
//! completes.
//!
//! Exit codes: 0 every case as expected; 1 an interop case failed; 2 the
//! negative control failed; 3 this OTP cannot run the check.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    PKCS_ED25519,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, NamedGroup, RootCertStore, ServerConfig, ServerConnection,
    StreamOwned,
};

const TIMEOUT: Duration = Duration::from_secs(20);

/// `(OTP's name for the group, what rustls must report)`.
const HYBRIDS: [(&str, NamedGroup); 2] = [
    ("secp384r1mlkem1024", NamedGroup::Unknown(0x11ED)),
    ("secp256r1mlkem768", NamedGroup::secp256r1MLKEM768),
];
const CLASSICAL_ONLY: &str = "x25519,secp256r1,secp384r1";

fn main() {
    let otp_bin = PathBuf::from(std::env::var("OTP_BIN").expect("OTP_BIN: OTP's bin directory"));
    let (release, crypto_lib) = otp_facts(&otp_bin);
    println!("OTP {release}, crypto library {crypto_lib}, against macula-pqc\n");

    let dir = std::env::temp_dir().join(format!("macula-pqc-otp-interop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let identity = Identity::write(&dir);
    let peer = Peer {
        escript: otp_bin.join("escript"),
        script: PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/otp_peer.escript"
        )),
        dir: dir.clone(),
    };

    let mut interop_failed = false;
    for (otp_name, expected) in HYBRIDS {
        for (role, outcome) in [
            ("OTP dials, we serve", we_serve(&peer, &identity, otp_name)),
            ("we dial, OTP serves", we_dial(&peer, &identity, otp_name)),
        ] {
            let pass = outcome == Ok(expected);
            interop_failed |= !pass;
            println!(
                "{role:<22} OTP offers {otp_name:<26} {:<34} {}",
                describe(&outcome),
                if pass { "PASS" } else { "FAIL" }
            );
            if let Err(e) = &outcome {
                println!("{:<22} {e}", "");
            }
        }
    }

    let mut control_failed = false;
    for (role, outcome) in [
        (
            "OTP dials, we serve",
            we_serve(&peer, &identity, CLASSICAL_ONLY),
        ),
        (
            "we dial, OTP serves",
            we_dial(&peer, &identity, CLASSICAL_ONLY),
        ),
    ] {
        let pass = outcome.is_err();
        control_failed |= !pass;
        println!(
            "{role:<22} OTP offers {CLASSICAL_ONLY:<26} {:<34} {}",
            describe(&outcome),
            if pass {
                "PASS (refused, as required)"
            } else {
                "FAIL: a classical-only peer agreed"
            }
        );
        if let Err(e) = &outcome {
            println!("{:<22} {e}", "");
        }
    }

    std::fs::remove_dir_all(&dir).unwrap();
    println!();
    if control_failed {
        println!("NEGATIVE CONTROL FAILED: a classical-only OTP peer agreed with macula-pqc.");
        std::process::exit(2);
    }
    if interop_failed {
        println!("INTEROP FAILED in at least one case.");
        std::process::exit(1);
    }
    println!(
        "macula-pqc and OTP's ssl agree on both hybrids in both roles; classical-only refused."
    );
}

fn describe(outcome: &Result<NamedGroup, String>) -> String {
    match outcome {
        Ok(NamedGroup::Unknown(0x11ED)) => "agreed on SecP384r1MLKEM1024".to_string(),
        Ok(group) => format!("agreed on {group:?}"),
        Err(_) => "no agreement".to_string(),
    }
}

/// The OTP release and the library its `crypto` is built on, checked for
/// the groups this needs before anything runs.
fn otp_facts(otp_bin: &Path) -> (String, String) {
    let out = Command::new(otp_bin.join("erl"))
        .args([
            "-noshell",
            "-eval",
            r#"
            {ok, _} = application:ensure_all_started(ssl),
            Needed = [secp384r1mlkem1024, secp256r1mlkem768],
            Missing = Needed -- ssl:groups(default),
            {ok, V} = file:read_file(filename:join([code:root_dir(), "releases",
                                     erlang:system_info(otp_release), "OTP_VERSION"])),
            [{Lib, _, Name}] = crypto:info_lib(),
            io:format("~s~n~s ~s~n~p~n", [string:trim(V), Lib, Name, Missing]),
            halt()."#,
        ])
        .output()
        .expect("run OTP's erl");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let lines: Vec<&str> = text.lines().collect();
    if !out.status.success() || lines.len() < 3 {
        eprintln!(
            "cannot query OTP at {}:\n{text}{}",
            otp_bin.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        std::process::exit(3);
    }
    if lines[2] != "[]" {
        eprintln!(
            "OTP {} lacks groups this check needs: {}",
            lines[0], lines[2]
        );
        std::process::exit(3);
    }
    (lines[0].to_string(), lines[1].to_string())
}

// ---------------------------------------------------------------------
// The two roles
// ---------------------------------------------------------------------

struct Peer {
    escript: PathBuf,
    script: PathBuf,
    dir: PathBuf,
}

impl Peer {
    fn spawn(&self, args: &[&str]) -> Child {
        Command::new(&self.escript)
            .arg(&self.script)
            .args(args)
            .arg(&self.dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start OTP's escript")
    }
}

/// OTP dials, `macula-pqc` serves. The group is what rustls reports; the
/// result is `Ok` only if OTP also completed the ping/pong.
fn we_serve(peer: &Peer, id: &Identity, otp_groups: &str) -> Result<NamedGroup, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().unwrap().port().to_string();
    let mut otp = peer.spawn(&["dial", &port, otp_groups]);
    let ours = (|| {
        let tcp = accept_within(&listener, TIMEOUT)?;
        tcp.set_read_timeout(Some(TIMEOUT)).unwrap();
        let conn = ServerConnection::new(Arc::new(id.server())).map_err(|e| e.to_string())?;
        let mut tls = StreamOwned::new(conn, tcp);
        let mut ping = [0u8; 4];
        tls.read_exact(&mut ping).map_err(|e| e.to_string())?;
        if &ping != b"ping" {
            return Err(format!("read {ping:?}, not ping"));
        }
        tls.write_all(b"pong").map_err(|e| e.to_string())?;
        tls.flush().map_err(|e| e.to_string())?;
        agreed_group(&tls.conn)
    })();
    both(ours, finish(&mut otp))
}

/// `macula-pqc` dials, OTP serves.
fn we_dial(peer: &Peer, id: &Identity, otp_groups: &str) -> Result<NamedGroup, String> {
    let mut otp = peer.spawn(&["serve", otp_groups]);
    let ours = (|| {
        let port = first_line_within(&mut otp, TIMEOUT)?
            .strip_prefix("port ")
            .ok_or("OTP did not report its port")?
            .trim()
            .to_string();
        let tcp = TcpStream::connect(format!("127.0.0.1:{port}")).map_err(|e| e.to_string())?;
        tcp.set_read_timeout(Some(TIMEOUT)).unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let conn = ClientConnection::new(Arc::new(id.client()), name).map_err(|e| e.to_string())?;
        let mut tls = StreamOwned::new(conn, tcp);
        tls.write_all(b"ping").map_err(|e| e.to_string())?;
        tls.flush().map_err(|e| e.to_string())?;
        let mut pong = [0u8; 4];
        tls.read_exact(&mut pong).map_err(|e| e.to_string())?;
        if &pong != b"pong" {
            return Err(format!("read {pong:?}, not pong"));
        }
        agreed_group(&tls.conn)
    })();
    both(ours, finish(&mut otp))
}

/// `Ok` only if both sides succeeded; otherwise every side's reason.
fn both(
    ours: Result<NamedGroup, String>,
    theirs: Result<(), String>,
) -> Result<NamedGroup, String> {
    match (ours, theirs) {
        (Ok(group), Ok(())) => Ok(group),
        (Ok(_), Err(t)) => Err(t),
        (Err(o), Ok(())) => Err(o),
        (Err(o), Err(t)) => Err(format!("{o} | {t}")),
    }
}

fn agreed_group(conn: &rustls::CommonState) -> Result<NamedGroup, String> {
    conn.negotiated_key_exchange_group()
        .map(|g| g.name())
        .ok_or_else(|| "no group negotiated".to_string())
}

fn accept_within(listener: &TcpListener, limit: Duration) -> Result<TcpStream, String> {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + limit;
    loop {
        match listener.accept() {
            Ok((tcp, _)) => {
                tcp.set_nonblocking(false).unwrap();
                return Ok(tcp);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(e) => return Err(format!("OTP never connected: {e}")),
        }
    }
}

/// The first line OTP prints. Read on a thread so a silent peer cannot
/// hang the check.
fn first_line_within(otp: &mut Child, limit: Duration) -> Result<String, String> {
    let stdout = otp.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let _ = reader.read_line(&mut line);
        let _ = tx.send((line, reader));
    });
    let (line, reader) = rx
        .recv_timeout(limit)
        .map_err(|_| "OTP printed nothing".to_string())?;
    // Hand the rest of stdout back, so `finish` can read OTP's verdict.
    otp.stdout = Some(reader.into_inner());
    Ok(line)
}

/// Waits for OTP's verdict: `ok`, or its error.
fn finish(otp: &mut Child) -> Result<(), String> {
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if let Some(status) = otp.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = otp.kill();
            return Err("OTP did not finish".to_string());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut out = String::new();
    if let Some(mut stdout) = otp.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    let verdict = out.lines().last().unwrap_or("").to_string();
    match status.success() && verdict == "ok" {
        true => Ok(()),
        false => Err(format!("OTP: {verdict}")),
    }
}

// ---------------------------------------------------------------------
// One identity, written for OTP and held for rustls
// ---------------------------------------------------------------------

/// An Ed25519 CA and a server certificate it signed. Ed25519 because OTP
/// checks an ECDSA certificate's curve against `supported_groups`, which
/// would force a classical group into a list meant to hold one hybrid.
///
/// ⚠ The two need DIFFERENT subject names. `rcgen` gives every
/// certificate the same default name, so the server certificate's issuer
/// would equal its own subject, and OTP rejects that as `selfsigned_peer`.
/// webpki accepts it, which is how the harness first failed only when OTP
/// was the client.
struct Identity {
    ca: CertificateDer<'static>,
    server_cert: CertificateDer<'static>,
    server_key: Vec<u8>,
}

impl Identity {
    fn write(dir: &Path) -> Identity {
        let ca_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name = common_name("macula-pqc interop CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let server_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_params.distinguished_name = common_name("localhost");
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

        std::fs::write(dir.join("ca.der"), ca.der()).unwrap();
        std::fs::write(dir.join("server.der"), server_cert.der()).unwrap();
        std::fs::write(dir.join("server.key.der"), server_key.serialize_der()).unwrap();
        Identity {
            ca: ca.der().clone(),
            server_cert: server_cert.der().clone(),
            server_key: server_key.serialize_der(),
        }
    }

    fn server(&self) -> ServerConfig {
        macula_pqc::server_builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![self.server_cert.clone()],
                PrivatePkcs8KeyDer::from(self.server_key.clone()).into(),
            )
            .unwrap()
    }

    fn client(&self) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.clone()).unwrap();
        macula_pqc::client_builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }
}

fn common_name(name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    dn
}
