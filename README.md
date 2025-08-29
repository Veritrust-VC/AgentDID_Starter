# AgentDID Starter

**AgentDID Starter** is a tiny, cross-platform tool to generate a **did:key** for your agent, store the private key encrypted with a **PIN**, and emit a DID Document and public JWK. It can **validate** your DID Document against the official **Veritrust Agent DID schema**.

- Works on **Windows / Linux / macOS**
- **GUI** (native window) and **CLI**
- Encrypted keystore (**AES-256-GCM**; key derived via **Argon2id** + HKDF)
- Outputs:
  - `did.txt` — DID string
  - `did-key.json` — DID Document (reference)
  - `public.jwk` — Public key (JWK)
  - `metadata.json` — keystore metadata (internal)
  - `keystore.enc` — encrypted private key
- **Validate** DID Document against:
  - `https://veritrust.vc/schemas/veritrust/did/Agent/1.0/agent_did_schema.json`

> ⚠️ Note: If your DID **does not start with `did:key:z…`**, schema validation may fail. Ensure you use a **spec-correct** `did:key` encoder for your chosen curve (P-256 or secp256k1).

---

## Quick Start (GUI)

1. Download or build the app (see “Build”).
2. Launch the app:
   - Windows: `target\release\agentdid-starter.exe`
   - macOS/Linux: `./target/release/agentdid-starter`
3. Choose an **output folder** (or keep default).
4. Enter a **PIN** (required) and click **Generate DID**.
5. Click **Validate against Veritrust schema** to verify `did-key.json`.
6. Use **Copy JSON** to copy the DID Document for your records.
7. The app remembers your last output folder (even if you move the EXE).

Footer link: https://veritrust.vc

---

## CLI Usage

```bash
# Generate DID (outputs to default ~/.agentdid)
agentdid-starter generate --pin 1234

# Custom output folder
agentdid-starter generate --pin 1234 --out ./mydid

# Show DID and DID Document
agentdid-starter show-did  --out ./mydid
agentdid-starter show-doc  --out ./mydid

# Reveal private key (only if created with export allowed; PIN required)
agentdid-starter show-key  --out ./mydid --pin 1234

# Backup / Restore
agentdid-starter backup  --out ./mydid --file backup.adk
agentdid-starter restore --out ./restored --file ./mydid/backup.adk --pin 1234

# Validate against Veritrust schema
agentdid-starter validate --out ./mydid
# or provide a custom schema URL
agentdid-starter validate --out ./mydid --schema https://example.com/schema.json
```

## Build
### Prerequisites
- Rust (stable)
- Windows: MSVC build tools + Windows 10/11 SDK
- macOS: Xcode command line tools
- Linux: build-essentials

### Commands
```bash
# Clone
git clone https://github.com/<you>/agentdid-starter.git
cd agentdid-starter

# Build (CLI + GUI)
cargo build --release

# (Optional) Windows resource metadata for “AgentDID Starter by Veritrust”
cargo build --release --features winres
```

Binaries:

- Windows: `target\release\agentdid-starter.exe`
- macOS/Linux: `./target/release/agentdid-starter`

### Where files are stored

By default:

Output folder: `~/.agentdid`

Config (remembers last output folder):

- Windows: `%APPDATA%\Veritrust\AgentDID\config.json`
- macOS: `~/Library/Application Support/veritrust/agentdid/config.json`
- Linux: `~/.config/veritrust/agentdid/config.json`

### Security

- Private key is sealed in `keystore.enc` using AES-256-GCM.
- KEK derived from your PIN using Argon2id + HKDF.
- Private key export is disabled by default; enable explicitly if needed.
- If you rotate your key, update your DID Document references accordingly.

### Validation

The `validate` command and the GUI validate button:

- Download the Veritrust Agent DID JSON Schema from
  https://veritrust.vc/schemas/veritrust/did/Agent/1.0/agent_did_schema.json
- Validate `did-key.json` against the schema
- Show a green check (success) or descriptive errors

### Roadmap

- Spec-correct did:key encoding (multicodec + base58btc) for P-256 / secp256k1
- did:web helper & publishing
- Local sign/prove API
- Key rotation in GUI

### License

MIT — see LICENSE

---

© Veritrust
