# Migration Phases: From QNAP to Bare Metal SOC

**Author:** Brian Chaplow
**Completed:** February 10-13, 2026

---

Built in 4 days (February 10-13, 2026), originally estimated at 4-6 weeks. This document tells the engineering story of migrating a home SOC from a QNAP-based v2 architecture to a purpose-built bare metal v3 platform. Each phase covers what was built, why specific decisions were made, what went wrong, and the measurable outcome.

---

## Phase 1: brisket Online

**Duration:** Day 1 (February 10, 2026)

### What Was Built

A Lenovo ThinkStation P3 Tiny Gen 2 (Intel Ultra 9 285, 64GB DDR5, NVIDIA RTX A1000 8GB) was provisioned from scratch as the new SOC core platform. Windows was wiped, Ubuntu Server 24.04 LTS installed, and the full base stack deployed: Docker Engine, NVIDIA drivers with Container Toolkit, Ollama for local LLM inference, Prometheus for metrics collection, and Grafana for dashboarding. The machine was connected to the 10G managed switch on VLAN 20 (SOC infrastructure) at 10.10.20.30.

### Key Decisions

**Ubuntu Server over Desktop:** Every megabyte of RAM matters when you are planning to run a SIEM indexer with an 8GB JVM heap, a SOAR platform, a DFIR server, and an LLM on the same box. Server edition with no GUI saves roughly 1-2GB of resident memory. Ubuntu 24.04 LTS was chosen specifically for the HWE kernel (6.17), which provides full Arrow Lake CPU support out of the box.

**Bare metal over Proxmox:** The RTX A1000 needs direct GPU access for CUDA-accelerated LLM inference and ML scoring. GPU passthrough on Proxmox works but adds latency and complexity. Since brisket runs only Docker containers (no VMs), a hypervisor would be pure overhead.

**Intra-VLAN micro-segmentation:** Brisket and the Kali attack box (sear) share VLAN 20. OPNsense cannot filter intra-VLAN L2 traffic because it never traverses the firewall. The solution was a 9-rule stateless ACL on the MokerLink managed switch, applied to sear's physical port (TE4). This permits only the specific TCP ports sear needs (Wazuh agent enrollment, OpenSearch queries, SSH, and Prometheus node_exporter) while denying everything else. The ACL is stateless, meaning every legitimate connection requires two rules: one for the outbound SYN and one for the inbound SYN-ACK return traffic.

### Challenges

**Secure Boot vs. NVIDIA DKMS:** The RTX A1000 requires the proprietary NVIDIA driver, which in turn requires DKMS kernel module signing. Secure Boot blocks unsigned kernel modules. Rather than setting up MOK (Machine Owner Key) enrollment for DKMS, Secure Boot was disabled in UEFI. This is acceptable in a lab environment where physical access is controlled.

**Storage layout:** The system shipped with a 1TB Gen5 NVMe. A second 2TB Gen4 NVMe (WD Black SN850X) was added and mounted at `/data` for Wazuh index storage. This separation ensures OS and container operations on the fast Gen5 drive are never bottlenecked by heavy indexer I/O on the data drive.

### Outcome

- GPU inference verified (Ollama loaded Qwen3 8B at 5.2GB VRAM, RTX A1000 detected)
- Prometheus scraping 6 targets (brisket node, brisket GPU, self, sear, smoker, pitcrew) -- all UP
- Grafana migrated from smokehouse with existing datasources preserved
- Tailscale mesh connected (for GCP VM agent enrollment)
- Intel NPU detected at `/dev/accel0` (deferred -- no workload requires it yet)

---

## Phase 2: Wazuh SIEM Deployment

**Duration:** Day 2 (February 11, 2026)

### What Was Built

Wazuh 4.14.2 was deployed as a single-node Docker Compose stack (Manager, Indexer, Dashboard) on brisket. Ten monitoring agents were enrolled across every host in the lab -- Linux servers, Windows workstations, a QNAP NAS, Proxmox hypervisors, and a cloud VM. A dedicated Fluent Bit pipeline was built to ship Zeek network metadata into namespace-separated indices on the same OpenSearch cluster. OPNsense was configured to forward firewall syslog over UDP.

### Key Decisions

**Zeek stays out of the Wazuh alert pipeline:** This was the single most important architectural decision in the entire migration. Zeek logs are network connection metadata (every TCP handshake, every DNS query, every HTTP request). Shipping them through Wazuh's rule engine would inflate alert counts by orders of magnitude and burn CPU cycles evaluating rules against data that is not alert-worthy. The industry standard (Security Onion, SELKS) is to send Zeek to a dedicated search index and Suricata to the SIEM. A separate Fluent Bit container on smokehouse ships 7 Zeek log types (conn, dns, http, ssl, ssh, notice, files) directly to `zeek-*` indices on brisket's OpenSearch, bypassing Wazuh entirely. Same cluster, different namespace.

**10-year TLS certificates:** Wazuh's Docker deployment generates 1-year self-signed certs by default. Silent cert expiry causes agents to disconnect with no obvious error. The certs were regenerated with a 10-year validity (expire 2036) using `wazuh-certs-tool.sh`, eliminating a common operational surprise.

**Agent deployment via evil-winrm:** The Windows domain controller (DC01) and workstation (WS01) are on VLAN 30, accessible from sear on VLAN 20 via OPNsense inter-VLAN routing. Rather than logging into each Windows VM individually, the Wazuh MSI was deployed remotely using evil-winrm with domain administrator credentials -- the same lateral movement technique an attacker would use, repurposed for legitimate administration.

### Challenges

**Suricata JSON decoder overflow:** Wazuh's default `analysisd.decoder_order_size` is 256 tokens. Suricata eve.json events routinely exceed this with nested flow metadata, HTTP headers, and packet payloads. Alerts were silently dropped until `internal_options.conf` was tuned to 1024.

**Wazuh field types vs. soc-ml expectations:** The ML pipeline was built against v2's flat OpenSearch schema where ports and byte counts were numeric types. In Wazuh, most Suricata fields land under `data.*` as `keyword` type -- even ports and byte counts are strings. The soc-ml extraction layer needed explicit int/float casts added for every numeric feature.

**PITBOSS legacy Fluent Bit:** A forgotten Fluent Bit service on the Windows management laptop was attempting to ship events to smokehouse's pre-VLAN IP (192.168.50.10). The traffic was being NAT'd through OPNsense and generating persistent firewall blocks. The `FluentBitWinlogs` service was stopped and disabled; Wazuh now handles all PITBOSS telemetry.

### Outcome

- 10 monitored endpoints (9 agents + OPNsense syslog) across 5 VLANs and GCP cloud
- 7 Zeek indices (`zeek-conn`, `zeek-dns`, `zeek-http`, `zeek-ssl`, `zeek-ssh`, `zeek-notice`, `zeek-files`) with proper field types via custom index template
- ISM lifecycle policies configured: alerts hot 7 days, warm, delete at 90 days; Zeek delete at 30 days; rollover at 30GB with force_merge
- 24,284+ Suricata alerts validated in Wazuh Dashboard on day one

---

## Phase 3: Hard Cutover

**Duration:** Day 2 (February 11, 2026)

### What Was Built

The v2 SIEM stack on smokehouse was decommissioned and smokehouse was converted to a sensor-only role. All critical data was backed up before the cut. OpenSearch, OpenSearch Dashboards, Fluent Bit, and the custom soc-automation Python scripts were stopped. Suricata, Zeek, and the new Wazuh agent continued running.

### Key Decisions

**Hard cut, not gradual migration:** Running dual stacks on smokehouse (v2 OpenSearch + new Wazuh agent shipping to brisket) would have consumed all 16GB of RAM on a machine already at 88% utilization. The approach was surgical: back up everything, stop the old stack, validate the new stack, move on. If v3 failed, the v2 containers were preserved (not removed) and could be restarted.

**Keep InfluxDB and Telegraf on smokehouse:** The existing Proxmox infrastructure dashboards in Grafana depend on InfluxDB as a datasource. Rather than re-instrumenting all Proxmox metrics collection, InfluxDB and Telegraf were left running. Prometheus handles the new SOC metrics; InfluxDB handles legacy infrastructure metrics.

### Challenges

**Automation gap:** Stopping soc-automation meant no AbuseIPDB enrichment, no Cloudflare auto-blocking, and no Discord watch turnover digests until Shuffle SOAR was deployed in Phase 5. This was a known, accepted gap -- the v2 Python cron scripts could not be adapted to query Wazuh's index schema quickly enough to justify keeping them running.

**Sysmon gap on Windows endpoints:** After cutover, Sysmon process creation events (Event ID 1) were not observed from DC01 or WS01. Windows Security events (4624 logon, 4674 privilege use) were flowing, but Sysmon either was not installed or was not configured to log to a channel the Wazuh agent was monitoring. This was flagged for follow-up.

### Outcome

- 38GB of v2 OpenSearch data backed up (89.7 million historic alerts preserved)
- 167 saved dashboard objects exported as NDJSON
- smokehouse RAM usage dropped from ~13GB to ~5GB (10.9GB free -- massive relief for a 16GB machine)
- All 9 agents confirmed active and reporting to brisket post-cutover
- 30,106 Suricata alerts + 32,747 Zeek documents validated on v3

---

## Phase 4: Case Management

**Duration:** Day 2 (February 11, 2026)

### What Was Built

TheHive 4 and Cortex 3 were deployed on a new LXC container (LXC 200) on the pitcrew Proxmox host, providing case management and observable enrichment capabilities that did not exist in v2. Five Cortex analyzers were configured: AbuseIPDB, VirusTotal, Shodan, Abuse Finder, and Google DNS.

### Key Decisions

**TheHive 4 over TheHive 5:** TheHive 5 free edition was evaluated first but proved unusable -- it restricts the free tier to zero organizations, zero Cortex server connections, and effectively no case creation. TheHive 4.1.24-1 is fully open source with no artificial feature gates. A StrangeBee community license was requested for a potential future upgrade, but TheHive 4 provides everything a single-operator SOC needs.

**pitcrew over brisket:** TheHive, Cortex, and their Elasticsearch 7.17 backend are all JVM processes. JVM resident memory bloat (typically 1.3-1.5x configured heap) would compete directly with Wazuh Indexer's JVM on brisket. Placing them on pitcrew, which had 26GB of idle RAM, eliminates this contention. Shuffle connects to TheHive and Cortex via HTTP API calls across the VLAN -- loosely coupled, no performance impact.

### Challenges

**Cortex Docker job_directory bug:** Cortex runs analyzers as sibling Docker containers. For this to work, the `job_directory` host path must exactly match the path inside the Cortex container. If the Docker volume mount maps `/opt/thehive/cortex-jobs` on the host to `/tmp/cortex-jobs` in the container, Cortex passes `/tmp/cortex-jobs` to the Docker socket, but the host creates the sibling container looking for that path on the host filesystem -- where it does not exist. The fix is making the paths identical on both sides.

### Outcome

- LXC 200: 4 cores, 8GB RAM, 40GB disk, Ubuntu 24.04 at 10.10.30.22
- TheHive Case #1 created, observables enriched via Cortex (GoogleDNS resolved 8.8.8.8, Abuse_Finder returned WHOIS contacts)
- 5 analyzers operational (AbuseIPDB, VirusTotal, Shodan, Abuse_Finder, GoogleDNS)
- 2.9GB used of 8GB allocated -- well within budget
- Wazuh agent installed (agent 010, total now 10 agents)

---

## Phase 5: Shuffle SOAR

**Duration:** Day 2 (February 11, 2026)

### What Was Built

Shuffle SOAR was deployed on brisket via Docker Compose, replacing the v2 cron-driven Python automation scripts with a visual, event-driven workflow engine. Two core workflows were built: WF1 (Threat Enrichment and Auto-Block) which takes a Wazuh alert, enriches it via AbuseIPDB, scores it with the ML model, optionally blocks via Cloudflare, creates a TheHive case, and sends a Discord notification; and WF2 (Watch Turnover Digest) which generates Navy-style watch relief reports every 12 hours with aggregated alert statistics.

### Key Decisions

**Shuffle over n8n or Tines:** Shuffle is purpose-built for security orchestration with native Wazuh and TheHive integrations. n8n is a general-purpose automation tool. Tines has better polish but is SaaS-only for the full feature set. Shuffle runs entirely on-premises, which matters when the SOAR platform needs to reach internal APIs on private VLANs.

**Workflow variables, never hardcoded credentials:** Every API key, URL, and password is stored as a Shuffle workflow variable (`$varname`). This was established as an inviolable convention after the first workflow accidentally had a hardcoded API key in an `execute_python` action. Changing a credential means updating one variable -- all actions referencing it update automatically.

### Challenges

Shuffle on-premises has a steep learning curve with numerous undocumented behaviors that consumed significant debugging time:

**Variable substitution quirks:** The correct syntax is `$varname`, not `$WORKFLOW_VARIABLE.varname`. The latter fails silently with "Failed finding WORKFLOW_VARIABLE." Action labels must use underscores -- spaces or special characters break `$variable` substitution in downstream references.

**execute_python output wrapping:** Every `execute_python` action wraps stdout in `{"success": true, "message": <stdout>}`. All downstream actions must reference the `.message.` path, not the raw output. This was not documented anywhere and required reading Shuffle source code to diagnose.

**Webhook body access:** The start node cannot use `$exec_argument` to access the webhook body. The correct accessor is `self.full_execution["execution_argument"]` -- another undocumented behavior.

**Port 1514 conflict:** Shuffle's Tenzir component binds to port 1514, which collides with Wazuh Manager's agent enrollment port. Setting `SHUFFLE_TENZIR_DISABLE=true` in the Shuffle environment resolves this.

### Outcome

- WF1: End-to-end alert enrichment validated (AbuseIPDB score 100, Cloudflare block, TheHive case created, Discord notification sent)
- WF2: 12-hour watch digest schedule running (0605/1805 EST)
- Cloudflare auto-blocking intentionally disabled via branch condition (`HONEYPOT_DISABLED`) to preserve honeypot research data collection
- Wazuh integratord configured to forward level 8+ alerts to WF1 webhook

---

## Phase 6: Velociraptor DFIR

**Duration:** Day 2 (February 11, 2026)

### What Was Built

Velociraptor v0.75.3 server was deployed on brisket as a Docker container, providing on-demand digital forensics and incident response capability across the lab. Clients were installed on 7 endpoints spanning Linux servers, Windows workstations, and the Windows management laptop.

### Key Decisions

**Docker deployment on brisket over standalone:** Velociraptor server is remarkably lightweight (~49MB RAM), making it an ideal Docker workload. Running it alongside the other brisket services keeps the forensic capability co-located with the SIEM and SOAR platforms for tight integration (Shuffle can trigger Velociraptor artifact collection via API).

**Deploy to all platforms, not just targets:** Velociraptor was installed on attack hosts (sear), infrastructure (smoker, pitcrew), Windows AD (DC01, WS01), and even the management laptop (PITBOSS). In a real incident, the compromised host could be any of these -- limiting forensic capability to only known targets would be a gap.

### Challenges

**MokerLink ACL update:** Sear's ACL on the MokerLink switch was too restrictive -- it did not permit TCP traffic to brisket's Velociraptor port (8000). A new PERMIT rule was added at sequence 35 (before the DENY at sequence 40) to allow `sear -> brisket TCP dst_port 8000`.

**WS01 Windows Firewall blocking agent:** The Velociraptor client on WS01 could not reach the server. Windows Firewall was blocking the outbound connection. After confirming the correct firewall exception, the client was deployed via SMB file transfer and installed as a local Windows service.

### Outcome

- 7 Velociraptor clients enrolled and checking in (smoker, pitcrew, brisket, PITBOSS, DC01, WS01, sear)
- On-demand forensic artifact collection capability across all major platforms
- Server RAM footprint: ~49MB (trivial compared to other brisket workloads)

---

## Phase 7: Caldera Adversary Emulation

**Duration:** Day 2-3 (February 11-12, 2026)

### What Was Built

MITRE Caldera v5.3.0 was deployed on the smoker Proxmox host as a Docker container, providing automated adversary emulation capability mapped to MITRE ATT&CK techniques. Four Sandcat agents were deployed on victim hosts (WS01, DVWA, Metasploitable 3 Linux, Metasploitable 3 Windows), and the first automated Discovery campaign was executed to validate that Wazuh detects the emulated attack activity.

### Key Decisions

**Caldera on smoker, not brisket:** Caldera is an adversary emulation platform -- it belongs on the same network segment as the targets it is attacking. Smoker hosts all VLAN 40 targets and has 17GB of RAM headroom. Running adversary emulation from the SOC platform would be architecturally wrong and would make it harder to validate that detection actually works across network boundaries.

**Sear is NOT a Caldera agent:** Sear is the attacker -- it runs manual tools (Metasploit, Nmap, Burp Suite) and the `run_attack.sh` framework. Caldera emulates adversaries on victim hosts. Installing a Caldera agent on sear would duplicate what the existing attack framework already does and would blur the distinction between red team tooling and adversary emulation.

### Challenges

**Caldera campaign configuration sensitivity:** Caldera v5.3.0 campaigns require very specific settings: `auto_close: false` (otherwise campaigns terminate before agents can retrieve links), `source: basic` (the fact source ID, not a descriptive name), and full adversary UUIDs (truncated UUIDs cause 0-link failures with no error message). These requirements are not well-documented and required multiple failed campaign attempts to discover.

**Windows agent persistence:** Caldera Sandcat agents on Windows needed Scheduled Tasks for persistence. Without persistence, agents disappeared on reboot. With persistence, they survived reboots but the Scheduled Tasks themselves consumed resources and needed cleanup between campaigns.

### Outcome

- 4 Sandcat agents active (WS01, DVWA, Metasploitable 3 Linux, Metasploitable 3 Windows)
- First Discovery campaign: T1033 (System Owner), T1087.001 (Local Account), T1057 (Process Discovery)
- 106 Wazuh alerts generated from WS01 during the campaign -- detection validated
- Adversary emulation platform operational for purple team exercises

---

## Phase 8: ML Pipeline v3

**Duration:** Day 3-4 (February 12-13, 2026)

### What Was Built

The custom ML threat detection pipeline was adapted from v2's OpenSearch schema to v3's Wazuh index format, retrained on fresh campaign data, and deployed as a GPU-accelerated scoring API on brisket. Thirteen Caldera campaigns were executed to generate diverse ground-truth training data, producing 3,868 attack-labeled alerts across multiple MITRE ATT&CK techniques. Six models were trained on 1.28 million records with 102 engineered features, plus a hybrid model combining supervised classification with unsupervised anomaly detection.

### Key Decisions

**PR-AUC over ROC-AUC as the primary metric:** The dataset is heavily imbalanced -- legitimate traffic vastly outnumbers attacks. ROC-AUC can look deceptively good even when the model barely catches true positives. Precision-Recall AUC focuses on how well the model finds needles in haystacks, which is what a SOC analyst actually cares about.

**Temporal train/test split:** Random splits would allow the model to see "future" attacks during training, causing data leakage that inflates test metrics. Temporal splits (train on earlier data, test on later data) simulate real deployment conditions where the model only sees the past.

**GPU-accelerated inference on brisket:** The trained XGBoost model was deployed as a FastAPI container (ml-scorer) on port 5002, sharing the RTX A1000 with Ollama via time-division: Ollama releases VRAM after 5 minutes of idle (`OLLAMA_KEEP_ALIVE=5m`), XGBoost scoring runs take seconds. If both fire simultaneously, XGBoost falls back to CPU on the Ultra 9 285.

### Challenges

**Wazuh field mapping layer:** Every field in the v2 pipeline assumed flat OpenSearch field names (`src_ip`, `dest_port`, `bytes_toserver`). Wazuh nests these under `data.*` (`data.src_ip`, `data.dest_port`, `data.flow.bytes_toserver`) and stores most as `keyword` type. A translation layer was added to soc-ml's extraction module that maps v3 field paths back to v2 names and casts types.

**Caldera campaign volume for training data:** A single Discovery campaign produces dozens of alerts, but the ML pipeline needs thousands of labeled attack samples across diverse technique categories. Thirteen campaigns were executed over two days, generating 4,874 links (1,349 success, 1,110 queued, 264 timeout, 66 visibility) and 218,000+ Wazuh alerts. The 40 Sandcat agents that accumulated across these campaigns (37 on WS01 alone) eventually consumed all of WS01's RAM, requiring a full VM rebuild in Phase 10.

**DataFrame.get() scalar bug:** The ml-scorer's `FeatureEngineer` used `pd.DataFrame.get('column', 0)` to handle missing columns. When a column is absent, this returns the scalar integer `0`, not a Series. Calling `.fillna(0)` on a scalar `int` throws an AttributeError. A `_safe_col()` static method was added that always returns a `pd.Series`, fixing 14 instances across 5 methods.

### Outcome

- XGBoost binary classifier: **PR-AUC 0.9998** (target was 0.70)
- 6 models trained: XGBoost, LightGBM, RandomForest, LogisticRegression, IsolationForest, SelfTrainingClassifier
- Hybrid scoring: `(1-w) * supervised_prob + w * anomaly_score` for zero-day coverage
- 102 engineered features including 31 Zeek connection features
- ml-scorer deployed to brisket Docker at port 5002, integrated into Shuffle WF1

---

## Phase 9: Ollama LLM Integration

**Duration:** Day 3 (February 12, 2026)

### What Was Built

The locally-hosted Qwen3 8B language model (running on the RTX A1000 via Ollama) was integrated into four Shuffle SOAR workflows, adding AI-powered triage, narrative generation, and detection gap analysis. Two new workflows were built from scratch: WF3 (Detection Gap Analyzer) that compares Caldera campaign techniques against Wazuh detections and identifies coverage gaps, and WF5 (Daily Alert Cluster Triage) that classifies the noisiest alert patterns overnight for morning review.

### Key Decisions

**Qwen3 8B over larger models:** The RTX A1000 has 8GB VRAM. Qwen3 8B quantized (Q4_K_M) fits in ~5.5GB, leaving headroom for CUDA context. Larger models (14B+) would require CPU offloading, which works but drops throughput to 10-15 tokens/second -- too slow for interactive SOAR workflows that need responses in seconds.

**`/no_think` prompting:** Qwen3 uses internal `<think>` reasoning tokens that count against the output token budget (`num_predict`). With the default `num_predict: 100`, the model's internal reasoning exhausts the budget before producing any visible output. The fix: prepend `/no_think` to every prompt and set `num_predict: 1000-2000`. All `<think>` tags are stripped from the response with regex before use.

### Challenges

**Ollama network binding:** Ollama defaults to binding on `127.0.0.1:11434`, which means Docker containers running Shuffle workflows cannot reach it. Setting `OLLAMA_HOST=0.0.0.0:11434` in the systemd service configuration fixes this, but the failure mode is a silent timeout with no error message indicating the cause.

**LLM output breaking JSON substitution:** Shuffle's HTTP action performs string substitution: `{"content":"$variable"}`. When the LLM output contains double quotes (which it invariably does), the substituted JSON is syntactically invalid. The fix: sanitize all LLM output with `.replace('"', "'").replace("\\", "")` before passing it to any downstream action that embeds it in JSON.

**Discord 2000 character limit:** Watch turnover digests with MITRE ATT&CK narratives frequently exceed Discord's message length limit. The digest must be truncated to 1,950 characters with a clean ellipsis. Keeping sections concise (single top IP, single top agent, top 3 rules) helps stay under the limit without truncation.

**execute_python cannot reach external HTTPS:** Shuffle's Orborus worker containers have limited outbound networking. Attempting to POST to Discord's webhook URL from `execute_python` returns a 403. The workaround: use Shuffle's HTTP app action (which runs in the backend container with full network access) for all external API calls.

### Outcome

- 4 Ollama integrations across 4 workflows (WF1 triage, WF2 narrative, WF3 gap analysis, WF5 cluster classification)
- WF3 computes MITRE ATT&CK detection coverage percentage and provides per-gap recommendations
- WF5 classifies alert clusters as CAMPAIGN / ROUTINE / INVESTIGATE / MISCONFIG and auto-creates TheHive alerts for INVESTIGATE items
- All LLM workflows staggered 3+ hours apart to avoid GPU contention

---

## Phase 10: ELK Stack (Dual-SIEM)

**Duration:** Day 3 (February 12, 2026)

### What Was Built

A full Elastic Stack (Elasticsearch 8.17, Kibana, Logstash, Fleet Server) was deployed on a new LXC container (LXC 201) on pitcrew, establishing a dual-SIEM architecture alongside Wazuh. Four Elastic Agents were enrolled on key hosts, 214 detection rules were enabled covering six MITRE ATT&CK tactic categories, and 36 pre-built dashboards were imported alongside a custom SOC v3 ELK Overview dashboard.

### Key Decisions

**Dual-SIEM is an interview differentiator:** Enterprise SOCs commonly run multiple SIEM platforms during evaluations, migrations, or for defense-in-depth. Running both Wazuh and Elastic provides direct comparison experience -- the exact question hiring managers ask: "How do Wazuh and Elastic compare?" The answer becomes a lived experience, not textbook knowledge.

**Dual-agent deployment over log forwarding:** Wazuh Agents ship to brisket. Elastic Agents ship to pitcrew. Two independent collection frameworks, two independent pipelines, no dependency between them. If either SIEM goes down, the other continues operating. The overhead is modest: Wazuh Agent ~100MB, Elastic Agent ~200MB per host.

**LXC over VM:** Elasticsearch, Kibana, Logstash, and Fleet Server are all containerized services. Running them inside a VM inside an LXC would be double-virtualization. A privileged LXC with Docker provides near-native performance and simpler resource management on pitcrew's constrained 32GB.

### Challenges

**WS01 required a complete rebuild:** During Phase 8, 37 Caldera Sandcat agents accumulated on WS01 (each campaign deployed a new agent). The AtomicTestService persistence mechanism consumed all available RAM. The VM was unrecoverable. A new WS01 was built from scratch: SeaBIOS (not OVMF -- UEFI caused display issues on Proxmox), 4 cores, 6GB RAM, virtio disk. The VM was rejoined to the smokehouse.local domain, all agents (Wazuh, Velociraptor, Elastic, Caldera) were redeployed, and a clean Proxmox snapshot was taken as a recovery point.

**SeaBIOS over OVMF for Windows 10 on Proxmox:** OVMF (UEFI) firmware on Proxmox caused display rendering issues with the Windows 10 VM -- the console would freeze or show corrupted output during boot. SeaBIOS (legacy BIOS) works reliably. This is a known Proxmox quirk with certain Windows versions and VGA configurations.

**pitcrew RAM budget is tight:** With DC01 (4GB), WS01 (4GB), TheHive LXC 200 (8GB), and ELK LXC 201 (10GB), pitcrew runs at approximately 26GB of its 32GB -- only 6GB headroom. If Elasticsearch needs more heap, Logstash can be run on-demand during ingest configuration changes rather than 24/7, reclaiming ~2GB. This was documented as an operational tradeoff rather than solved with hardware.

**ELK containers do not auto-start on LXC reboot:** The Docker containers inside LXC 201 do not start automatically when the LXC reboots. This requires a manual `docker compose up -d` after any pitcrew or LXC restart. A systemd service could automate this but was deferred.

### Outcome

- Elasticsearch 8.17 + Kibana + Fleet Server + Logstash running in Docker on LXC 201
- 4 Elastic Agents enrolled (smokehouse, sear, DC01, WS01)
- 214 detection rules enabled: Defense Evasion (57), Credential Access (45), Execution (38), Persistence (31), Privilege Escalation (29), Lateral Movement (21)
- 36 pre-built dashboards + custom [SOC v3] ELK Overview (11 panels)
- 30-day Elastic Platinum trial activated for advanced security features
- Dual-SIEM architecture operational: Wazuh primary on brisket, ELK secondary on pitcrew

---

## Phase 11: Proxmox Backup Server

**Duration:** Day 4 (February 13, 2026)

### What Was Built

Proxmox Backup Server was deployed on a new LXC container (LXC 300) on smoker, with an NFS datastore pointing to smokehouse's 17TB RAID array. Automated backup schedules were configured for all critical VMs and LXCs across both Proxmox hypervisors: pitcrew backs up daily (DC01, WS01, TheHive LXC, ELK LXC) and smoker backs up weekly (DVWA, Metasploitable 3 Linux, Metasploitable 3 Windows).

### Key Decisions

**PBS over simple vzdump cron:** Proxmox Backup Server provides deduplication, incremental backups, and a web UI for backup management and verification. Simple `vzdump` cron jobs would work but produce full backups every time, consuming significantly more storage and offering no deduplication across similar VMs.

**NFS to smokehouse rather than local storage:** Smoker's local SSD does not have room for backup data from both hypervisors. Smokehouse has 17TB of RAID storage that was previously consumed by the v2 OpenSearch cluster. With OpenSearch decommissioned, this storage is available for backups without any additional hardware cost.

**Aggressive prune schedule:** Keep-last 3, daily 7, weekly 4, monthly 3. In a home lab where VMs can be rebuilt quickly, long-term retention of dozens of backup snapshots wastes storage without adding value. The prune schedule keeps enough history to recover from recent mistakes while garbage collection (Saturday 07:00) reclaims space.

### Challenges

**NFS mount persistence across LXC reboots:** The NFS mount inside LXC 300 needed to be configured in `/etc/fstab` with the correct options (`_netdev`, `nofail`) to survive reboots gracefully. Without `_netdev`, the system attempts to mount the NFS share before the network is up, causing a boot hang.

### Outcome

- PBS LXC 300: 2 cores, 2GB RAM at 10.10.30.24
- NFS datastore `smokehouse-store` on 17TB RAID array
- pitcrew daily backups at 02:00: 4 guests (DC01, WS01, LXC 200, LXC 201)
- smoker weekly backups Sunday 03:00: 3 guests (DVWA, Metasploitable 3 Linux, Metasploitable 3 Windows)
- Prune policy: keep-last 3, daily 7, weekly 4, monthly 3
- Weekly garbage collection: Saturday 07:00
- `pbs-smokehouse` storage added to both Proxmox hosts

---

## Lessons Learned

The 4-day migration produced a substantial body of operational knowledge that is difficult to find in documentation. These lessons are the kind of engineering detail that separates someone who has deployed these tools from someone who has only read about them.

### Resource Planning on Thin Clients

The ThinkStation P340 Tiny machines (pitcrew and smoker) have 32GB RAM each. This sounds generous until you start stacking JVM processes. TheHive, Cortex, Cassandra, and Elasticsearch each want 1-2GB heap, and JVM resident memory is typically 1.3-1.5x the configured heap. Placing TheHive/Cortex on pitcrew instead of brisket was not just a nice-to-have -- it was essential to avoid four JVM processes competing with Wazuh Indexer's 8GB JVM on the same machine. Every RAM allocation decision cascaded: bumping DC01 and WS01 from 2GB to 4GB (needed for triple-agent + Sysmon overhead) tightened pitcrew to 6GB headroom, which meant Logstash had to be treated as an on-demand service rather than always-on.

### Proxmox PVE Kernel Quirks

Proxmox's custom kernel differs from upstream Debian in ways that matter for container workloads. Docker targets on smoker require `privileged: true` because the PVE kernel's cgroup configuration does not expose the device nodes that unprivileged containers expect. Macvlan networking does not work when the parent interface is bridge-enslaved (which it always is on Proxmox) -- ipvlan L2 is the correct alternative for giving containers dedicated IPs on target VLANs.

### Windows Agent Deployment at Scale

Deploying agents (Wazuh, Velociraptor, Elastic, Caldera) to Windows VMs revealed several patterns. Evil-winrm is effective for MSI deployment using domain credentials, but Windows Firewall blocks outbound connections by default for new services. Each agent needs its own firewall exception. Windows Defender's Tamper Protection must be disabled through the Windows Security UI first, then through GPO and registry -- the order matters. And the biggest lesson: Caldera's AtomicTestService persistence creates resource leaks that accumulate across campaigns until the VM becomes unrecoverable. Always snapshot before running adversary emulation campaigns, and always clean up agent persistence mechanisms between runs.

### Shuffle SOAR Undocumented Behaviors

Shuffle on-premises is powerful but has a significant documentation gap. The on-premises scheduler is interval-based, not cron-based -- the `frequency` field must be an integer (seconds), and cron expressions in the UI are cosmetic. System cron triggering the workflow via curl is the correct architecture for hitting exact times. Updating a workflow via the API silently deregisters schedule triggers even though the status field still shows "running." Orborus caches interval schedules in memory, and the only way to clear ghost executions is restarting both shuffle-backend and shuffle-orborus. After restarting the backend, the frontend (nginx) must also be restarted because it caches the old backend container's IP, resulting in 502 errors.

### Dual-SIEM Architecture in Practice

Running Wazuh and Elastic simultaneously is not just resume padding -- it exposes real architectural differences. Wazuh's strength is its opinionated, integrated platform: manager, agents, rules engine, active response, and dashboard all designed to work together. Elastic's strength is flexibility: Fleet-managed agents, a rich query language (KQL/EQL), pre-built detection rules mapped to MITRE ATT&CK, and an ML framework. The tradeoff is operational overhead: dual agents on every host, dual sets of detection rules to maintain, and dual dashboards to monitor. For a single operator, this is manageable. For a team, the conversation about which SIEM to standardize on becomes very informed.

### The 4-Day Factor

The original estimate of 4-6 weeks assumed sequential work with learning curves. The actual 4-day timeline was possible because every technology had been researched in advance (the 1,700-line planning document existed before brisket was unboxed), Docker Compose deployments eliminated manual installation, and each phase had clear success criteria. The lesson is not "this should always take 4 days" -- it is that thorough planning compresses execution dramatically. The planning document took longer to write than the migration took to execute.

---

## Final State Summary

| Metric | Value |
|--------|-------|
| Total hosts monitored | 10 (9 agents + 1 syslog) |
| Wazuh detection rules | Built-in engine + custom decoders |
| Elastic detection rules | 214 |
| SOAR workflows | 8 (WF1-WF8) |
| ML models trained | 6 + hybrid |
| XGBoost PR-AUC | 0.9998 |
| Velociraptor DFIR clients | 7 |
| Caldera agents | 4 |
| LLM integrations | 7 workflows using Qwen3 8B |
| Zeek indices | 7 (conn, dns, http, ssl, ssh, notice, files) |
| Backup coverage | 7 guests across 2 hypervisors |
| Total cluster RAM | 176 GB across 6 hosts |
| Total GPU VRAM | 12 GB (RTX A1000 8GB + GTX 1650 Ti 4GB) |
| Migration duration | 4 days (estimated 4-6 weeks) |
