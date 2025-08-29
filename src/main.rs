use clap::{Parser, Subcommand};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

use anyhow::{anyhow, Context};
use base64::Engine;
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;
use time::format_description;
use url::Url;

const DEFAULT_SCHEMA_URL: &str = "https://veritrust.vc/schemas/veritrust/did/Agent/1.0/agent_did_schema.json";

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Debug, Parser)]
#[command(
    name = "AgentDID Starter",
    version,
    about = "did:key generator with PIN-encrypted keystore"
)]
struct Cli {
    /// Run GUI (no args) or CLI subcommands
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate a did:key (P-256) and write artifacts
    Generate {
        /// Output directory (defaults to ~/.agentdid)
        #[arg(long)]
        out: Option<PathBuf>,
        /// PIN to protect the keystore (prompting recommended in real app)
        #[arg(long)]
        pin: String,
        /// Allow exporting (revealing) private key later
        #[arg(long, default_value_t = false)]
        allow_export: bool,
    },
    /// Print DID string
    ShowDid {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print reference DID Document JSON
    ShowDoc {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Reveal private key (if allowed)
    ShowKey {
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        pin: String,
    },
    /// Create encrypted backup bundle
    Backup {
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value = "backup.adk")]
        file: String,
    },
    /// Restore from encrypted backup bundle
    Restore {
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        file: String,
        #[arg(long)]
        pin: String,
    },
    /// Validate did-key.json against the Veritrust schema
    Validate {
        #[arg(long)]
        out: Option<PathBuf>,
        /// Optional custom schema URL
        #[arg(long, default_value = DEFAULT_SCHEMA_URL)]
        schema: String,
    },
}

fn default_outdir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| ".".into())
        .join(".agentdid")
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct AppConfig {
    last_out_dir: Option<String>,
}

fn config_dir() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| default_outdir());
    base.join("veritrust").join("agentdid")
}

fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

fn load_config() -> AppConfig {
    let p = config_path();
    match fs::read(&p) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Default::default(),
    }
}

fn save_config(cfg: &AppConfig) -> anyhow::Result<()> {
    fs::create_dir_all(config_dir()).ok();
    fs::write(config_path(), serde_json::to_vec_pretty(cfg)?)?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct KeystoreMeta {
    alg: String,      // ES256
    curve: String,    // P-256
    kid: String,      // #keys-1
    exportable: bool, // was --allow-export set?
    created_at: String,
    // Argon2 password hash (PHC string) so we can re-derive keys safely
    argon2_phc: String,
    // AES-GCM nonce used to encrypt the private key
    nonce_b64: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DidDoc {
    #[serde(rename = "@context")]
    context: Vec<String>,
    id: String,
    #[serde(rename = "verificationMethod")]
    verification_method: Vec<VerificationMethod>,
    authentication: Vec<String>,
    #[serde(rename = "assertionMethod")]
    assertion_method: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerificationMethod {
    id: String,
    #[serde(rename = "type")]
    r#type: String,
    controller: String,
    #[serde(rename = "publicKeyJwk")]
    public_key_jwk: Jwk,
}

fn main() -> eframe::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(cmd) => {
            run_cli(cmd);
            Ok(())
        }
        None => run_gui(),
    }
}

fn run_cli(cmd: Commands) {
    match cmd {
        Commands::Generate {
            out,
            pin,
            allow_export,
        } => {
            let out = out.unwrap_or_else(default_outdir);
            fs::create_dir_all(&out).ok();
            let bundle = generate_did_key(&pin, allow_export).expect("generate failed");
            write_outputs(&out, &bundle).expect("failed writing outputs");
            println!("✅ DID generated. See {}", out.display());
        }
        Commands::ShowDid { out } => {
            let out = out.unwrap_or_else(default_outdir);
            let did = fs::read_to_string(out.join("did.txt")).expect("no did.txt");
            println!("{did}");
        }
        Commands::ShowDoc { out } => {
            let out = out.unwrap_or_else(default_outdir);
            let doc = fs::read_to_string(out.join("did-key.json")).expect("no did-key.json");
            println!("{doc}");
        }
        Commands::ShowKey { out, pin } => {
            let out = out.unwrap_or_else(default_outdir);
            let priv_pem = decrypt_private_key(&out, &pin)
                .expect("cannot decrypt (wrong PIN?) or not exportable");
            println!("{priv_pem}");
        }
        Commands::Backup { out, file } => {
            let out = out.unwrap_or_else(default_outdir);
            let ks = out.join("keystore.enc");
            let meta = out.join("metadata.json");
            let did = out.join("did.txt");
            let doc = out.join("did-key.json");
            let jwk = out.join("public.jwk");
            let bundle = out.join(file);

            let mut zip = zip::ZipWriter::new(fs::File::create(&bundle).unwrap());
            let opts = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);

            for (name, p) in [
                ("keystore.enc", &ks),
                ("metadata.json", &meta),
                ("did.txt", &did),
                ("did-key.json", &doc),
                ("public.jwk", &jwk),
            ] {
                zip.start_file(name, opts).unwrap();
                let bytes = fs::read(p).unwrap_or_default();
                use std::io::Write;
                zip.write_all(&bytes).unwrap();
            }
            zip.finish().unwrap();
            println!("✅ Backup created at {}", bundle.display());
        }
        Commands::Restore { out, file, pin: _ } => {
            let out = out.unwrap_or_else(default_outdir);
            fs::create_dir_all(&out).ok();
            let mut zip =
                zip::ZipArchive::new(fs::File::open(&file).expect("open backup")).expect("zip");
            for i in 0..zip.len() {
                let mut f = zip.by_index(i).unwrap();
                let out_path = out.join(f.name());
                if f.name().ends_with('/') {
                    fs::create_dir_all(&out_path).ok();
                    continue;
                }
                let mut buf = Vec::new();
                use std::io::Read;
                f.read_to_end(&mut buf).unwrap();
                fs::write(out_path, buf).unwrap();
            }
            println!("✅ Backup restored to {}", out.display());
        }
        Commands::Validate { out, schema } => {
            let out = out.unwrap_or_else(default_outdir);
            let doc_path = out.join("did-key.json");
            let res = fs::read_to_string(&doc_path)
                .with_context(|| format!("missing {}", doc_path.display()))
                .and_then(|doc_str| {
                    let doc_json: serde_json::Value =
                        serde_json::from_str(&doc_str).context("did-key.json parse error")?;
                    let schema_json = fetch_schema(&schema)?;
                    validate_doc_with_schema(&doc_json, &schema_json)
                });
            match res {
                Ok(()) => println!("✅ did-key.json is valid against the schema."),
                Err(e) => println!("❌ Validation failed: {e}"),
            }
        }
    }
}

/* ---------- Core generation ---------- */

struct DidBundle {
    did: String,
    doc_json: String,
    public_jwk_json: String,
    ciphertext: Vec<u8>,
    meta: KeystoreMeta,
}

fn generate_did_key(pin: &str, exportable: bool) -> anyhow::Result<DidBundle> {
    // 1) keypair (P-256)
    let signing_key = SigningKey::random(&mut OsRng);
    let verify_key = signing_key.verifying_key();
    let ep = verify_key.to_encoded_point(false); // uncompressed SEC1 point
    let x_bytes = ep.x().ok_or_else(|| anyhow!("missing X"))?;
    let y_bytes = ep.y().ok_or_else(|| anyhow!("missing Y"))?;
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x_bytes);
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y_bytes);
    let public_jwk = Jwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x,
        y,
    };
    let public_jwk_json = serde_json::to_string_pretty(&public_jwk)?;

    // 2) DID string (POC fallback)
    let did = build_did_key_fallback(&public_jwk_json);

    // DID Document (reference)
    let kid = format!("{did}#keys-1");
    let vm = VerificationMethod {
        id: kid.clone(),
        r#type: "JsonWebKey2020".into(),
        controller: did.clone(),
        public_key_jwk: public_jwk.clone(),
    };
    let doc = DidDoc {
        context: vec!["https://www.w3.org/ns/did/v1".into()],
        id: did.clone(),
        verification_method: vec![vm],
        authentication: vec![kid.clone()],
        assertion_method: vec![kid.clone()],
    };
    let doc_json = serde_json::to_string_pretty(&doc)?;

    // 3) Private key PEM
    let private_pem = signing_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)?
        .to_string();

    // 4) Derive KEK from PIN using Argon2id; store PHC string (with salt/params)
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    let phc = argon
        .hash_password(pin.as_bytes(), &salt)
        .map_err(anyhow::Error::msg)?
        .to_string();

    // Re-derive raw bytes from PHC for HKDF
    let parsed = PasswordHash::new(&phc).map_err(anyhow::Error::msg)?;
    Argon2::default()
        .verify_password(pin.as_bytes(), &parsed)
        .map_err(anyhow::Error::msg)?; // check correctness now
    let hk = Hkdf::<Sha256>::new(
        None,
        parsed
            .hash
            .ok_or_else(|| anyhow::anyhow!("no hash"))?
            .as_bytes(),
    );
    let mut kek = [0u8; 32];
    hk.expand(b"agentdid-keystore", &mut kek)
        .map_err(anyhow::Error::msg)?;

    // AES-256-GCM encrypt
    let cipher = Aes256Gcm::new_from_slice(&kek)?;
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, private_pem.as_bytes())
        .map_err(anyhow::Error::msg)?;

    let rfc3339 = format_description::well_known::Rfc3339;
    let meta = KeystoreMeta {
        alg: "ES256".into(),
        curve: "P-256".into(),
        kid: "#keys-1".into(),
        exportable,
        created_at: time::OffsetDateTime::now_utc().format(&rfc3339).unwrap(),
        argon2_phc: phc,
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
    };

    Ok(DidBundle {
        did,
        doc_json,
        public_jwk_json,
        ciphertext,
        meta,
    })
}

fn write_outputs(out: &PathBuf, b: &DidBundle) -> anyhow::Result<()> {
    fs::create_dir_all(out).ok();
    fs::write(out.join("did.txt"), &b.did)?;
    fs::write(out.join("did-key.json"), &b.doc_json)?;
    fs::write(out.join("public.jwk"), &b.public_jwk_json)?;
    fs::write(
        out.join("metadata.json"),
        serde_json::to_vec_pretty(&b.meta)?,
    )?;
    fs::write(out.join("keystore.enc"), &b.ciphertext)?;
    Ok(())
}

fn decrypt_private_key(out: &PathBuf, pin: &str) -> anyhow::Result<String> {
    let meta: KeystoreMeta = serde_json::from_slice(&fs::read(out.join("metadata.json"))?)?;
    if !meta.exportable {
        anyhow::bail!("private key export was not allowed at creation time");
    }
    let ct = fs::read(out.join("keystore.enc"))?;
    if ct.is_empty() {
        anyhow::bail!("keystore.enc is empty/missing");
    }
    // Re-derive KEK from stored Argon2 PHC + provided PIN
    let parsed = PasswordHash::new(&meta.argon2_phc).map_err(anyhow::Error::msg)?;
    Argon2::default()
        .verify_password(pin.as_bytes(), &parsed)
        .map_err(|_| anyhow::anyhow!("invalid PIN"))?;
    let hk = Hkdf::<Sha256>::new(
        None,
        parsed
            .hash
            .ok_or_else(|| anyhow::anyhow!("no hash"))?
            .as_bytes(),
    );
    let mut kek = [0u8; 32];
    hk.expand(b"agentdid-keystore", &mut kek)
        .map_err(anyhow::Error::msg)?;

    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(meta.nonce_b64.as_bytes())
        .map_err(anyhow::Error::msg)?;
    let cipher = Aes256Gcm::new_from_slice(&kek)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(anyhow::Error::msg)?;
    let pem = String::from_utf8(plaintext)?;
    Ok(pem)
}

fn fetch_schema(schema_url: &str) -> anyhow::Result<serde_json::Value> {
    let url = Url::parse(schema_url).context("bad schema URL")?;
    let resp = reqwest::blocking::get(url).context("schema GET failed")?;
    let status = resp.status();
    anyhow::ensure!(status.is_success(), "schema fetch status {}", status);
    let v = resp
        .json::<serde_json::Value>()
        .context("invalid schema JSON")?;
    Ok(v)
}

fn validate_doc_with_schema(
    doc: &serde_json::Value,
    schema: &serde_json::Value,
) -> anyhow::Result<()> {
    use jsonschema::{Draft, JSONSchema};
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft7)
        .compile(schema)
        .context("compile schema failed")?;
    if let Err(errors) = compiled.validate(doc) {
        let mut msg = String::new();
        for e in errors {
            use std::fmt::Write as _;
            let _ = writeln!(&mut msg, "- {e}");
        }
        anyhow::bail!("Schema validation failed:\n{msg}");
    }
    Ok(())
}

/* ---- did:key helpers ---- */
fn build_did_key_fallback(public_jwk_json: &str) -> String {
    // Fallback: not spec-perfect; OK for POC if ssi isn't available.
    let digest = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(public_jwk_json.as_bytes());
        let out = h.finalize();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out)
    };
    format!("did:key:{}", digest)
}

/* ---------- Minimal GUI ---------- */
fn run_gui() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "AgentDID Starter",
        native_options,
        Box::new(|_cc| Ok(Box::new(GuiApp::default()))),
    )
}

struct GuiApp {
    pin: String,
    allow_export: bool,
    status: String,
    did: String,
    out_dir: String,
    doc_preview: String,
}

impl Default for GuiApp {
    fn default() -> Self {
        let mut app = GuiApp {
            pin: String::new(),
            allow_export: false,
            status: String::new(),
            did: String::new(),
            out_dir: String::new(),
            doc_preview: String::new(),
        };
        let cfg = load_config();
        if let Some(path) = cfg.last_out_dir {
            if PathBuf::from(&path).join("did.txt").exists() {
                app.out_dir = path;
            }
        }
        if app.out_dir.is_empty() {
            let def = default_outdir();
            if def.join("did.txt").exists() {
                app.out_dir = def.to_string_lossy().to_string();
            }
        }
        app
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("AgentDID Starter");
            ui.separator();

            ui.label("Output folder:");
            ui.add(egui::TextEdit::singleline(&mut self.out_dir));
            let out = if self.out_dir.trim().is_empty() {
                default_outdir()
            } else {
                PathBuf::from(self.out_dir.trim())
            };

            ui.separator();
            ui.label("Enter PIN to protect your keystore:");
            ui.add(egui::TextEdit::singleline(&mut self.pin).password(true));

            ui.checkbox(
                &mut self.allow_export,
                "Allow private key export (optional)",
            );

            if ui.button("Generate did:key (P-256)").clicked() {
                fs::create_dir_all(&out).ok();
                match generate_did_key(&self.pin, self.allow_export) {
                    Ok(b) => {
                        if let Err(e) = write_outputs(&out, &b) {
                            self.status = format!("Error writing files: {e}");
                        } else {
                            self.did = b.did.clone();
                            self.status = format!("DID generated. Files in {}", out.display());
                            if let Ok(s) = fs::read_to_string(out.join("did-key.json")) {
                                self.doc_preview = s;
                            }
                            let _ = save_config(&AppConfig {
                                last_out_dir: Some(out.to_string_lossy().to_string()),
                            });
                        }
                    }
                    Err(e) => self.status = format!("Error: {e}"),
                }
            }

            if ui.button("Validate against Veritrust schema").clicked() {
                let out = if self.out_dir.trim().is_empty() {
                    default_outdir()
                } else {
                    PathBuf::from(self.out_dir.trim())
                };
                let doc_path = out.join("did-key.json");
                match fs::read_to_string(&doc_path)
                    .map_err(|e| anyhow!("read {} failed: {e}", doc_path.display()))
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).map_err(anyhow::Error::msg))
                    .and_then(|doc| {
                        let schema = fetch_schema(DEFAULT_SCHEMA_URL)?;
                        validate_doc_with_schema(&doc, &schema)
                    }) {
                    Ok(()) => self.status = "✅ Valid per Veritrust schema".into(),
                    Err(e) => self.status = format!("❌ Invalid: {e}"),
                }
            }

            if !self.did.is_empty() {
                ui.separator();
                ui.label("Your DID:");
                ui.code(&self.did);

                if ui
                    .button("Reveal private key (requires export allowed + PIN)")
                    .clicked()
                {
                    match decrypt_private_key(&out, &self.pin) {
                        Ok(pem) => {
                            self.status = "Private key (PEM) copied to clipboard.".into();
                            ui.output_mut(|o| o.copied_text = pem);
                        }
                        Err(e) => self.status = format!("Cannot reveal key: {e}"),
                    }
                }
            }

            if !self.doc_preview.is_empty() {
                ui.separator();
                ui.label("DID Document (did-key.json):");
                egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                    ui.code(&self.doc_preview);
                });
                if ui.button("Copy JSON").clicked() {
                    ui.output_mut(|o| o.copied_text = self.doc_preview.clone());
                    self.status = "DID JSON copied to clipboard".into();
                }
            }

            ui.separator();
            ui.label(&self.status);

            ui.separator();
            ui.horizontal_wrapped(|ui| {
                ui.label("© Veritrust • ");
                ui.hyperlink_to("https://veritrust.vc", "https://veritrust.vc");
            });
        });
    }
}
