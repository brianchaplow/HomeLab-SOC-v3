# SOC Infrastructure Redesign — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Trim redundant tooling (v2 metrics stack), deploy haccp as bare-metal ELK + Arkime PCAP node, add OpenCTI threat intelligence platform on pitcrew, establish Sigma/YARA operational practices, and re-enable Cloudflare auto-blocking.

**Architecture:** Five phases executed during rack migration downtime. Phase A (cleanup) can run now. Phase B (haccp standup) requires Computrace clearance + physical access. Phases C-E build sequentially on prior phases. No seamless cutover needed — personal SOC with no active campaigns.

**Tech Stack:** Ubuntu 24.04, Docker Compose, Elasticsearch 8.17, Kibana, Fleet Server, Logstash, Arkime, OpenCTI, NVIDIA driver, Tailscale, Wazuh, Velociraptor, Shuffle SOAR, Prometheus, Sigma, YARA

**Design doc:** `docs/plans/2026-03-14-soc-infrastructure-redesign.md`

---

## Chunk 1: Phase A — Pre-haccp Cleanup (Can Do Now)

> **Note:** Tasks 1-5 are independent and can be executed in any order or in parallel.

### Task 1: Re-enable Cloudflare Auto-Block in Shuffle WF1

**Context:** WF1 on brisket has a `HONEYPOT_DISABLED` branch condition that bypasses Cloudflare IP blocking. The honeypot campaign ended 2026-03-12. Re-enable auto-blocking.

**Where:** Shuffle UI at `https://10.10.20.30:3443` → Workflows → WF1

- [ ] **Step 1: Open WF1 in Shuffle UI**

Navigate to `https://10.10.20.30:3443`, login (admin / see credentials), open WF1 (enrichment + block + dedup workflow).

- [ ] **Step 2: Find and remove the HONEYPOT_DISABLED branch condition**

Locate the branch/condition node that checks `HONEYPOT_DISABLED`. This bypasses the Cloudflare blocking action. Either:
- Delete the branch condition entirely, or
- Change the condition so the Cloudflare block action always executes

The Cloudflare block action uses workflow variables `$cf_api_token` and `$cf_account_id`.

- [ ] **Step 3: Save and test WF1**

Save the workflow. Trigger a test execution (manual or via webhook) and verify the Cloudflare block action is no longer bypassed. Check the execution log in Shuffle to confirm the block path is taken.

- [ ] **Step 4: Verify in Discord**

Confirm the Discord notification from WF1 includes blocking information (not skipped).

### Task 2: Prune Dead Containers on brisket

**Context:** 6 exited Shuffle worker containers on brisket are consuming disk space.

- [ ] **Step 1: SSH to brisket and list dead containers**

```bash
ssh bchaplow@10.10.20.30
docker ps -a --filter "status=exited" --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
```

Verify you see ~6 exited containers (names like `elegant_almeida`, `gracious_mendel`, etc.).

- [ ] **Step 2: Prune exited containers**

```bash
docker container prune -f
```

Expected: `Deleted Containers:` listing ~6 container IDs.

- [ ] **Step 3: Verify only expected containers remain**

```bash
docker ps -a --format "table {{.Names}}\t{{.Status}}" | sort
```

Expected: All remaining containers show `Up` status. No exited containers. Active containers: wazuh stack (3), shuffle stack (4), velociraptor, ml-scorer, grafana, prometheus, capitol-signals, tenzir-node.

### Task 3: Decommission v2 Metrics Stack on smokehouse

**Context:** InfluxDB v2, Grafana, and Telegraf containers on smokehouse served the honeypot campaign and legacy Proxmox metrics. Campaign is over, Prometheus/Grafana on brisket covers metrics. Decommission all three.

- [ ] **Step 1: SSH to smokehouse and list metrics containers**

```bash
ssh -p 2222 bchaplow@10.10.20.10
/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "(influx|grafana|telegraf)"
```

Expected: `influxdb`, `grafana`, `telegraf` all showing `Up`.

- [ ] **Step 2: Stop the three containers**

```bash
/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker stop influxdb grafana telegraf
```

- [ ] **Step 3: Remove the containers**

```bash
/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker rm influxdb grafana telegraf
```

- [ ] **Step 4: Verify only sensor containers remain**

```bash
/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker ps --format "table {{.Names}}\t{{.Status}}"
```

Expected: Only `elastic-agent`, `fluent-bit-zeek`, `wazuh-agent`, `zeek`, `suricata-live` remain running.

- [ ] **Step 5: Verify brisket Prometheus still scrapes smokehouse node-exporter**

```bash
ssh bchaplow@10.10.20.30 "curl -s http://localhost:9090/api/v1/targets | python3 -c \"import sys,json; targets=json.load(sys.stdin)['data']['activeTargets']; [print(t['scrapeUrl'], t['health']) for t in targets]\""
```

Expected: All targets show `up`, including smokehouse (if it has a node-exporter). The decommissioned services should NOT affect Prometheus scraping.

### Task 4: Decommission Telegraf on pitcrew

**Context:** Telegraf on pitcrew ships Proxmox metrics to smokehouse InfluxDB (now decommissioned). Remove it entirely.

- [ ] **Step 1: SSH to pitcrew and stop Telegraf**

```bash
ssh root@10.10.30.20
systemctl stop telegraf
systemctl disable telegraf
```

- [ ] **Step 2: Remove Telegraf package and repo**

```bash
apt remove --purge telegraf -y
rm /etc/apt/sources.list.d/influxdata.list
rm /etc/apt/trusted.gpg.d/influxdata-archive.asc
rm -f /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg
rm -f /etc/apt/keyrings/influxdata-archive-keyring.gpg
```

- [ ] **Step 3: Verify clean apt update**

```bash
apt update
```

Expected: No InfluxData repo in the output. No GPG errors. Only debian, proxmox, wazuh, and ceph repos.

- [ ] **Step 4: Verify Telegraf is gone**

```bash
systemctl status telegraf
```

Expected: `Unit telegraf.service could not be found.`

### Task 5: Decommission Telegraf on smoker

**Context:** Same as pitcrew — Telegraf ships to now-dead InfluxDB.

- [ ] **Step 1: SSH to smoker and stop Telegraf**

```bash
ssh root@10.10.30.21
systemctl stop telegraf
systemctl disable telegraf
```

- [ ] **Step 2: Remove Telegraf package**

```bash
apt remove --purge telegraf -y
```

Note: smoker does not have an influxdata apt repo in `/etc/apt/sources.list.d/` (it uses tailscale, wazuh, and pve-no-subscription repos). No repo cleanup needed.

- [ ] **Step 3: Verify clean**

```bash
systemctl status telegraf
```

Expected: `Unit telegraf.service could not be found.`

- [ ] **Step 4: Verify apt update is clean**

```bash
apt update
```

Expected: No errors. No InfluxData repo references.

---

## Chunk 2: Phase B — haccp Standup (After Computrace Clears)

> **Hardware pre-requisites with lead time:**
> - 2x 10GBase-T SFP+ RJ45 transceivers (order before Phase B — needed for Task 10)
> - USB 2.5GbE adapter (already owned)
> - Ubuntu 24.04 Server ISO on USB stick
>
> Tasks 6-9 (OS, network, Docker, ELK) can proceed without the SFP+ transceivers. Task 10 (Arkime SPAN capture) requires the hardware.

### Task 6: Install Ubuntu 24.04 on haccp (Physical Access Required)

**Context:** haccp is a ThinkStation P340 Tiny with 2TB WD SN720 NVMe + 1TB Vansuny NVMe. Currently on VLAN 20 (10.10.20.25) for Computrace deactivation. Will move to VLAN 30 (10.10.30.25).

**Prerequisites:** Computrace cleared. Ubuntu 24.04 Server ISO on USB stick.

- [ ] **Step 1: Boot from USB installer**

- Hostname: `haccp`
- User: `bchaplow`
- During partitioning: install on the **2TB WD SN720** as `/`, ext4, full disk, no LVM
- Do NOT partition the 1TB Vansuny during install
- Install OpenSSH server

- [ ] **Step 2: Partition and mount the 1TB drive**

After first boot, SSH in and identify the 1TB drive:

```bash
lsblk
# Identify the ~1TB device (likely /dev/nvme1n1)
```

Partition and format:

```bash
sudo parted /dev/nvme1n1 mklabel gpt
sudo parted /dev/nvme1n1 mkpart primary ext4 0% 100%
sudo mkfs.ext4 /dev/nvme1n1p1
```

Create mount point and add to fstab:

```bash
sudo mkdir -p /opt/arkime/raw
echo "$(blkid -s UUID -o value /dev/nvme1n1p1) /opt/arkime/raw ext4 defaults,noatime 0 2" | sudo tee -a /etc/fstab
sudo mount -a
```

- [ ] **Step 3: Verify dual drive layout**

```bash
lsblk -o NAME,SIZE,MOUNTPOINT,FSTYPE
df -h | grep -E "(nvme|Filesystem)"
```

Expected: 2TB mounted at `/`, 1TB mounted at `/opt/arkime/raw`.

### Task 7: Network Configuration

**Context:** Change haccp from temporary VLAN 20 to permanent VLAN 30.

- [ ] **Step 1: Change TE8 VLAN on MokerLink**

Login to MokerLink switch web UI at `10.10.10.2`. Navigate to VLAN settings for port TE8. Change PVID from VLAN 20 to VLAN 30.

- [ ] **Step 2: Configure static IP on haccp**

Edit netplan config on haccp:

```bash
sudo nano /etc/netplan/01-netcfg.yaml
```

```yaml
network:
  version: 2
  ethernets:
    # Identify the onboard NIC name with `ip link show`
    enp0s31f6:  # adjust if different
      addresses:
        - 10.10.30.25/24
      routes:
        - to: default
          via: 10.10.30.1
      nameservers:
        addresses: [10.10.10.1, 8.8.8.8]
```

```bash
sudo netplan apply
```

- [ ] **Step 3: Verify connectivity**

```bash
# From haccp
ping -c 3 10.10.30.1        # OPNsense VLAN 30 gateway
ping -c 3 10.10.20.30       # brisket (cross-VLAN)
ping -c 3 10.10.30.20       # pitcrew (same VLAN)
ping -c 3 8.8.8.8           # internet
```

All should succeed. If cross-VLAN fails, check OPNsense rules (should work — same rules that LXC 201 at 10.10.30.23 uses).

### Task 8: Install Docker and NVIDIA Driver

- [ ] **Step 1: Install Docker**

```bash
sudo apt update && sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update && sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker bchaplow
```

Log out and back in for group change.

- [ ] **Step 2: Verify Docker**

```bash
docker run --rm hello-world
```

Expected: `Hello from Docker!`

- [ ] **Step 3: Install NVIDIA driver**

```bash
sudo apt install -y ubuntu-drivers-common
sudo ubuntu-drivers devices
# Should show Quadro P1000 with recommended driver
sudo ubuntu-drivers autoinstall
sudo reboot
```

- [ ] **Step 4: Verify NVIDIA driver**

```bash
nvidia-smi
```

Expected: Shows Quadro P1000, 4096 MiB memory, driver version.

### Task 9: Deploy ELK Stack via Docker Compose

**Context:** Elasticsearch 8.17 + Kibana + Fleet Server + Logstash. HTTPS with self-signed CA. This is the same stack that runs on LXC 201, deployed fresh on bare metal.

- [ ] **Step 1: Create directory structure**

```bash
sudo mkdir -p /opt/elk
cd /opt/elk
```

- [ ] **Step 2: Create Docker Compose file**

Create `/opt/elk/docker-compose.yml`. Reference the existing compose file on LXC 201 for the exact image versions and configuration patterns:

```bash
ssh root@10.10.30.20 "pct exec 201 -- cat /opt/elk/docker-compose.yml" > /tmp/elk-reference.yml
```

Key configuration points:
- ES image: `docker.elastic.co/elasticsearch/elasticsearch:8.17.0` (match LXC 201 version)
- ES heap: `-Xms12g -Xmx12g` via `ES_JAVA_OPTS`
- ES data volume: named Docker volume on 2TB drive
- Kibana image: match ES version
- Fleet Server: match ES version, expose port 8220
- Logstash: match ES version, expose port 5044
- TLS: ES generates self-signed CA on first boot (`xpack.security.enabled=true`)
- Network: single Docker bridge network for inter-container communication

- [ ] **Step 3: Create .env file**

```bash
cat > /opt/elk/.env << 'EOF'
ELASTIC_PASSWORD=<PLATFORM_PASSWORD>
KIBANA_PASSWORD=<PLATFORM_PASSWORD>
CLUSTER_NAME=haccp-elk
LICENSE=basic
ES_PORT=9200
KIBANA_PORT=5601
FLEET_PORT=8220
LOGSTASH_PORT=5044
STACK_VERSION=8.17.0
ES_MEM_LIMIT=14g
KB_MEM_LIMIT=1g
LS_MEM_LIMIT=2g
FLEET_MEM_LIMIT=1g
EOF
chmod 600 /opt/elk/.env
```

- [ ] **Step 4: Start the ELK stack**

```bash
cd /opt/elk && docker compose up -d
```

Wait ~2 minutes for ES to initialize and generate certificates.

- [ ] **Step 5: Verify all containers are healthy**

```bash
docker compose ps
```

Expected: All containers running. ES shows `healthy`.

```bash
curl -k -u elastic:<PLATFORM_PASSWORD> https://localhost:9200
```

Expected: JSON response with cluster name `haccp-elk`, version `8.17.0`.

```bash
curl -s http://localhost:5601/api/status | python3 -c "import sys,json; print(json.load(sys.stdin)['status']['overall']['level'])"
```

Expected: `available`

### Task 10: Install Arkime

**Context:** Native install (not Docker) for raw NIC access. Arkime capture reads from the USB 2.5GbE adapter in promiscuous mode. Session metadata goes to the shared ES instance. PCAPs go to the 1TB drive.

**Prerequisites:** USB 2.5GbE adapter plugged in, SFP+ RJ45 transceiver installed in TE11 on MokerLink, mirror session 2 configured.

- [ ] **Step 1: Install SFP+ transceiver and configure mirror session**

Physical: Insert 10GBase-T SFP+ RJ45 transceiver into MokerLink TE11. Connect ethernet cable from haccp USB 2.5GbE adapter to the transceiver.

On MokerLink switch web UI (`10.10.10.2`):

```
mirror session 2 source interface te1-te9 both
mirror session 2 destination interface te11
```

If the switch rejects overlapping sources with session 1, fall back to:

```
mirror session 2 source interface te3,te4 both
mirror session 2 destination interface te11
```

- [ ] **Step 2: Verify mirrored traffic is reaching the USB NIC**

```bash
# Identify the USB NIC interface name first
ip link show
# Look for the USB 2.5GbE adapter — likely named enx<mac> or eth1 (no IP)

# Verify traffic is arriving on the capture interface
sudo tcpdump -i <USB_NIC_NAME> -c 10 --immediate-mode
```

Expected: You should see packets from various hosts on the network. If no traffic, check MokerLink mirror session 2 configuration and transceiver link status.

- [ ] **Step 3: Record the USB NIC interface name**

```bash
ip link show
# Look for the USB 2.5GbE adapter — likely named something like enx<mac> or eth1
# It should NOT have an IP address
```

Record the interface name (referred to as `$CAPTURE_NIC` below).

- [ ] **Step 3: Install Arkime dependencies**

```bash
sudo apt install -y wget curl libpcap-dev libyaml-dev
```

- [ ] **Step 4: Download and install Arkime**

```bash
# Check https://arkime.com/downloads for latest version
wget https://s3.us-east-1.amazonaws.com/files.molo.ch/builds/ubuntu-24.04/arkime_5.5.0-1_amd64.deb
sudo dpkg -i arkime_5.5.0-1_amd64.deb
```

- [ ] **Step 5: Configure Arkime**

Run the configuration script:

```bash
sudo /opt/arkime/bin/Configure
```

When prompted:
- Interface: `$CAPTURE_NIC` (the USB 2.5GbE interface name)
- Elasticsearch URL: `https://localhost:9200`
- Password: `<PLATFORM_PASSWORD>`
- Should Arkime install ES: **No** (already running)

Edit `/opt/arkime/etc/config.ini`:

```ini
[default]
elasticsearch=https://localhost:9200
pcapDir=/opt/arkime/raw
freeSpaceG=50
maxFileSizeG=2
# ES auth
elasticsearchBasicAuth=elastic:<PLATFORM_PASSWORD>
# TLS - skip verification for self-signed
elasticsearchSSLVerify=false
```

- [ ] **Step 6: Initialize Arkime in ES**

```bash
sudo /opt/arkime/db/db.pl --esuser elastic --espass <PLATFORM_PASSWORD> --esssl https://localhost:9200 init
```

This creates index templates, ILM policies, and the `arkime_sessions3-*` index pattern.

- [ ] **Step 7: Create Arkime admin user**

```bash
sudo /opt/arkime/bin/arkime_add_user.sh admin "Admin User" <PLATFORM_PASSWORD> --admin --esuser elastic --espass <PLATFORM_PASSWORD> --esssl https://localhost:9200
```

- [ ] **Step 8: Start Arkime services**

```bash
sudo systemctl enable arkimecapture
sudo systemctl enable arkimeviewer
sudo systemctl start arkimecapture
sudo systemctl start arkimeviewer
```

- [ ] **Step 9: Verify Arkime is capturing**

```bash
sudo systemctl status arkimecapture
# Should show "active (running)"

# Check PCAP files are being written
ls -la /opt/arkime/raw/
# Should see .pcap files appearing

# Check Arkime viewer
curl -s -u admin:<PLATFORM_PASSWORD> http://localhost:8005/api/eshealth
# Should return ES health info
```

- [ ] **Step 10: Verify Arkime sessions in ES**

```bash
curl -k -u elastic:<PLATFORM_PASSWORD> "https://localhost:9200/arkime_sessions3-*/_count"
```

Expected: `{"count": <some number>, ...}` — session documents being indexed.

### Task 11: Install SOC Agents and Monitoring

- [ ] **Step 1: Install Wazuh agent**

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update && sudo apt install -y wazuh-agent
```

Configure manager IP:

```bash
sudo sed -i 's/MANAGER_IP/10.10.20.30/' /var/ossec/etc/ossec.conf
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Verify on brisket:

```bash
ssh bchaplow@10.10.20.30 "sudo /var/ossec/bin/agent_control -l" | grep haccp
```

- [ ] **Step 2: Install Velociraptor client**

Download the client package from brisket. The Velociraptor server stores client installers that can be downloaded from the GUI or copied from an existing enrolled Linux host:

```bash
# Option 1: Copy the client config from an existing enrolled Linux host (e.g., pitcrew)
ssh root@10.10.30.20 "cat /etc/velociraptor/client.config.yaml" > /tmp/client.config.yaml
scp /tmp/client.config.yaml bchaplow@10.10.30.25:/tmp/

# On haccp — install the Velociraptor client package
# Download the matching version from GitHub releases (check brisket version: v0.75.3)
wget https://github.com/Velocidex/velociraptor/releases/download/v0.75.3/velociraptor_0.75.3_linux_amd64.deb
sudo dpkg -i velociraptor_0.75.3_linux_amd64.deb
sudo cp /tmp/client.config.yaml /etc/velociraptor/client.config.yaml
sudo systemctl enable velociraptor-client
sudo systemctl start velociraptor-client
```

Verify enrollment in Velociraptor GUI — should show haccp as a new client.

- [ ] **Step 3: Install Tailscale**

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

Authenticate via the URL provided. Verify:

```bash
tailscale status
```

Expected: haccp appears in the Tailscale mesh with a 100.x.x.x address.

**Record haccp's Tailscale IP** — you'll need it in Task 16 when repointing GCP Fluent Bit.

- [ ] **Step 4: Install Prometheus node-exporter**

```bash
sudo apt install -y prometheus-node-exporter
sudo systemctl enable prometheus-node-exporter
```

Verify:

```bash
curl -s http://localhost:9100/metrics | head -5
```

- [ ] **Step 5: Add haccp to Prometheus scrape targets on brisket**

SSH to brisket and edit the Prometheus config:

```bash
ssh bchaplow@10.10.20.30
# Find Prometheus config — likely in a Docker volume or bind mount
docker inspect prometheus --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}'
```

Add haccp to the scrape targets:

```yaml
- targets: ['10.10.30.25:9100']
  labels:
    instance: 'haccp'
```

Reload Prometheus:

```bash
docker exec prometheus kill -SIGHUP 1
# Or: curl -X POST http://localhost:9090/-/reload
```

Verify at `http://10.10.20.30:9090/targets` — haccp should show `UP`.

### Task 12: Set Up PCAP Archival Cron

- [ ] **Step 1: Create the archival script on haccp**

```bash
sudo cat > /opt/arkime/pcap-archive.sh << 'SCRIPT'
#!/bin/bash
# Archive Arkime PCAPs to smokehouse NFS before auto-expiry
# Runs weekly via cron. Uses tar + zstd compression per spec.

ARCHIVE_DIR="/mnt/smokehouse-nfs/pcap-archive"
PCAP_DIR="/opt/arkime/raw"
DATE=$(date +%Y-%m-%d)
ARCHIVE_FILE="${ARCHIVE_DIR}/pcap-${DATE}.tar.zst"

mkdir -p "$ARCHIVE_DIR"

# Tar + zstd compress PCAPs older than 1 day (avoid in-progress writes)
find "$PCAP_DIR" -name "*.pcap" -mtime +1 -print0 | \
  tar --null -T - -cf - | zstd -3 -o "$ARCHIVE_FILE"

FILE_COUNT=$(find "$PCAP_DIR" -name "*.pcap" -mtime +1 | wc -l)
ARCHIVE_SIZE=$(du -sh "$ARCHIVE_FILE" 2>/dev/null | cut -f1)

echo "$(date): Archived ${FILE_COUNT} PCAPs (${ARCHIVE_SIZE}) to ${ARCHIVE_FILE}" >> /var/log/pcap-archive.log
SCRIPT
sudo chmod +x /opt/arkime/pcap-archive.sh
```

Install zstd if not present:

```bash
sudo apt install -y zstd
```

- [ ] **Step 2: Mount smokehouse NFS share**

```bash
sudo apt install -y nfs-common
sudo mkdir -p /mnt/smokehouse-nfs
# Verify actual NFS export path on smokehouse first:
# ssh -p 2222 bchaplow@10.10.20.10 "showmount -e localhost" or check QNAP Shared Folders
echo "10.10.20.10:/share/SOC /mnt/smokehouse-nfs nfs defaults,noatime 0 0" | sudo tee -a /etc/fstab
sudo mount -a
ls /mnt/smokehouse-nfs/
```

Expected: NFS share contents visible.

```bash
sudo mkdir -p /mnt/smokehouse-nfs/pcap-archive
```

- [ ] **Step 3: Add weekly cron**

```bash
sudo crontab -e
```

Add:

```
# PCAP archival to smokehouse - Sunday 03:00 UTC
0 3 * * 0 /opt/arkime/pcap-archive.sh
```

---

## Chunk 3: Phase C — ELK Migration

### Task 13: Export from LXC 201

**Context:** Export all Kibana saved objects, detection rules, Fleet policies, and dashboards from the existing ELK on pitcrew LXC 201 before migrating to haccp.

- [ ] **Step 1: Export Kibana saved objects**

```bash
ssh root@10.10.30.20 "pct exec 201 -- bash -c 'curl -s -k -u elastic:<PLATFORM_PASSWORD> https://localhost:5601/api/saved_objects/_export -H \"kbn-xsrf: true\" -H \"Content-Type: application/json\" -d \"{\\\"type\\\": [\\\"dashboard\\\", \\\"visualization\\\", \\\"index-pattern\\\", \\\"search\\\", \\\"lens\\\", \\\"map\\\"], \\\"includeReferencesDeep\\\": true}\" > /tmp/kibana-export.ndjson'"
```

Copy to PITBOSS or haccp:

```bash
ssh root@10.10.30.20 "pct pull 201 /tmp/kibana-export.ndjson /tmp/kibana-export.ndjson"
scp root@10.10.30.20:/tmp/kibana-export.ndjson /tmp/
```

- [ ] **Step 2: Export Elastic detection rules**

```bash
ssh root@10.10.30.20 "pct exec 201 -- bash -c 'curl -s -k -u elastic:<PLATFORM_PASSWORD> https://localhost:5601/api/detection_engine/rules/_export -H \"kbn-xsrf: true\" > /tmp/detection-rules.ndjson'"
scp root@10.10.30.20:/tmp/detection-rules.ndjson /tmp/
```

- [ ] **Step 3: Snapshot honeypot indices for reference**

```bash
ssh root@10.10.30.20 "pct exec 201 -- bash -c 'curl -s -k -u elastic:<PLATFORM_PASSWORD> -X PUT https://localhost:9200/_snapshot/local_backup -H \"Content-Type: application/json\" -d \"{\\\"type\\\": \\\"fs\\\", \\\"settings\\\": {\\\"location\\\": \\\"/tmp/es-snapshots\\\"}}'"

ssh root@10.10.30.20 "pct exec 201 -- bash -c 'curl -s -k -u elastic:<PLATFORM_PASSWORD> -X PUT \"https://localhost:9200/_snapshot/local_backup/honeypot-final?wait_for_completion=true\" -H \"Content-Type: application/json\" -d \"{\\\"indices\\\": \\\"honeypot-*,apache-parsed-v2\\\"}'"
```

- [ ] **Step 4: Document Fleet agent enrollment tokens and policies**

```bash
ssh root@10.10.30.20 "pct exec 201 -- bash -c 'curl -s -k -u elastic:<PLATFORM_PASSWORD> https://localhost:5601/api/fleet/enrollment_api_keys -H \"kbn-xsrf: true\"'" | python3 -m json.tool > /tmp/fleet-enrollment-keys.json

ssh root@10.10.30.20 "pct exec 201 -- bash -c 'curl -s -k -u elastic:<PLATFORM_PASSWORD> https://localhost:5601/api/fleet/agent_policies -H \"kbn-xsrf: true\"'" | python3 -m json.tool > /tmp/fleet-policies.json
```

### Task 14: Import to haccp ELK

- [ ] **Step 1: Import Kibana saved objects**

```bash
scp /tmp/kibana-export.ndjson bchaplow@10.10.30.25:/tmp/
ssh bchaplow@10.10.30.25 "curl -s -k -u elastic:<PLATFORM_PASSWORD> -X POST https://localhost:5601/api/saved_objects/_import?overwrite=true -H 'kbn-xsrf: true' -F file=@/tmp/kibana-export.ndjson"
```

Expected: JSON response with `success: true` and count of imported objects.

- [ ] **Step 2: Import detection rules**

```bash
scp /tmp/detection-rules.ndjson bchaplow@10.10.30.25:/tmp/
ssh bchaplow@10.10.30.25 "curl -s -k -u elastic:<PLATFORM_PASSWORD> -X POST https://localhost:5601/api/detection_engine/rules/_import -H 'kbn-xsrf: true' -F file=@/tmp/detection-rules.ndjson"
```

Expected: JSON response showing 214 rules imported.

- [ ] **Step 3: Verify in Kibana**

Open `https://10.10.30.25:5601` in browser. Login as elastic. Verify:
- Dashboards present under Kibana → Dashboards
- Detection rules present under Security → Rules (should show 214)
- Index patterns configured

### Task 15: Re-enroll Fleet Agents

**Context:** 4 Fleet agents currently point to LXC 201 (10.10.30.23:8220). Repoint to haccp (10.10.30.25:8220).

Fleet agents: smokehouse, DC01, WS01, GCP VM.

- [ ] **Step 1: Create Fleet Server connection in haccp Kibana**

In Kibana → Fleet → Settings, verify Fleet Server URL is `https://10.10.30.25:8220`.

Create enrollment token for the agent policy.

- [ ] **Step 2: Re-enroll smokehouse Elastic Agent**

```bash
ssh -p 2222 bchaplow@10.10.20.10
# Find the elastic-agent container
/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker exec -it elastic-agent bash

# Inside the container:
elastic-agent enroll --url=https://10.10.30.25:8220 --enrollment-token=<NEW_TOKEN> --insecure
```

Alternatively, update the Fleet Server URL in the agent's configuration and restart.

- [ ] **Step 3: Re-enroll DC01 Fleet Agent**

RDP or WinRM to DC01 (10.10.30.40, Administrator / `<AD_DOMAIN_PASSWORD>`):

```powershell
& "C:\Program Files\Elastic\Agent\elastic-agent.exe" enroll --url=https://10.10.30.25:8220 --enrollment-token=<NEW_TOKEN> --insecure
Restart-Service "Elastic Agent"
```

- [ ] **Step 4: Re-enroll WS01 Fleet Agent**

Same process as DC01 on WS01 (10.10.30.41).

- [ ] **Step 5: Re-enroll GCP VM Fleet Agent**

```bash
ssh to GCP VM via Tailscale or gcloud:
gcloud compute ssh wordpress-1-vm --zone=us-east4-a

sudo elastic-agent enroll --url=https://10.10.30.25:8220 --enrollment-token=<NEW_TOKEN> --insecure
sudo systemctl restart elastic-agent
```

Note: GCP VM connects to haccp via Tailscale. Fleet Server URL should use haccp's Tailscale IP if the LAN IP isn't routable. Check `tailscale status` on haccp for its 100.x.x.x IP.

- [ ] **Step 6: Verify all 4 agents in haccp Kibana**

In Kibana → Fleet → Agents, verify 4 agents show `Healthy` status:
- smokehouse
- DC01
- WS01
- GCP VM (wordpress-1-vm)

### Task 16: Repoint GCP Fluent Bit

**Context:** Fluent Bit on GCP VM ships `apache-parsed-v2` access logs to ELK. Currently points to the former LXC 201 Tailscale endpoint. Repoint to haccp's Tailscale endpoint.

- [ ] **Step 1: SSH to GCP VM**

```bash
gcloud compute ssh wordpress-1-vm --zone=us-east4-a
# or: ssh bchaplow@<gcp-tailscale-ip>
```

- [ ] **Step 2: Update Fluent Bit output config**

Find the active Fluent Bit config:

```bash
sudo ls /etc/fluent-bit/ /fluent-bit/etc/ 2>/dev/null
```

Edit the Elasticsearch output section — change the `Host` from the former LXC 201 Tailscale IP to haccp's Tailscale IP:

```ini
[OUTPUT]
    Name  es
    Match *
    Host  <HACCP_TAILSCALE_IP>
    Port  9200
    tls   On
    tls.verify Off
    HTTP_User elastic
    HTTP_Passwd <PLATFORM_PASSWORD>
    ...
```

Note: Preserve any other existing output settings (Index, Type, etc.) from the current config. The key changes are `Host` (from LXC 201 Tailscale IP to haccp Tailscale IP) and ensuring TLS settings match since haccp uses HTTPS with self-signed CA.

- [ ] **Step 3: Restart Fluent Bit**

```bash
sudo systemctl restart fluent-bit
```

- [ ] **Step 4: Verify data flowing to haccp ES**

```bash
ssh bchaplow@10.10.30.25 "curl -k -u elastic:<PLATFORM_PASSWORD> 'https://localhost:9200/apache-parsed-v2/_count'"
```

Expected: Document count increasing.

### Task 17: Update Shuffle Variables and Clean Up

- [ ] **Step 1: Update Shuffle workflow variables on brisket**

Login to Shuffle UI (`https://10.10.20.30:3443`). Navigate to Workflow Variables (Admin → Workflow Variables or within each workflow's variable settings).

Update:
- `$elk_url` → `https://10.10.30.25:9200`
- `$elk_user` → `elastic` (same)
- `$elk_pass` → `<PLATFORM_PASSWORD>` (same or new if changed)

- [ ] **Step 2: Test Shuffle workflows that use ELK variables**

Manually trigger WF6 (Model Drift Detector) or WF8 (LLM Log Anomaly Finder) — they query ELK. Verify execution succeeds in Shuffle execution logs.

- [ ] **Step 3: Remove honeypot-wazuh-sync cron on brisket**

```bash
ssh bchaplow@10.10.20.30
crontab -e
```

Remove the commented-out honeypot sync line entirely:

```
# DECOMMISSIONED 2026-03-12T23:55:00Z */15 * * * * /usr/bin/python3 /home/bchaplow/honeypot-wazuh-sync.py >> /home/bchaplow/honeypot-wazuh-sync.log 2>&1
```

Optionally clean up the script and log:

```bash
rm ~/honeypot-wazuh-sync.py ~/honeypot-wazuh-sync.log
```

- [ ] **Step 4: Verify end-to-end data flow**

Check all data paths are working:

```bash
# Fleet agents reporting to haccp
ssh bchaplow@10.10.30.25 "curl -k -u elastic:<PLATFORM_PASSWORD> 'https://localhost:9200/.fleet-agents/_search?size=10&pretty' | grep 'local_metadata.host.name'"

# Arkime capturing
ssh bchaplow@10.10.30.25 "curl -k -u elastic:<PLATFORM_PASSWORD> 'https://localhost:9200/arkime_sessions3-*/_count'"

# Detection rules running
ssh bchaplow@10.10.30.25 "curl -k -u elastic:<PLATFORM_PASSWORD> 'https://localhost:5601/api/detection_engine/rules/_find?per_page=1' -H 'kbn-xsrf: true' | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"total\"])'"
```

- [ ] **Step 5: Shut down LXC 201 on pitcrew**

After confirming everything works on haccp:

```bash
ssh root@10.10.30.20
pct stop 201
pct destroy 201
```

Verify freed resources:

```bash
free -h
```

Expected: ~10GB more available than before.

---

## Chunk 4: Phase D — OpenCTI Deployment

### Task 18: Create OpenCTI LXC on pitcrew

- [ ] **Step 1: Download Ubuntu 24.04 container template**

```bash
ssh root@10.10.30.20
pveam update
pveam download local ubuntu-24.04-standard_24.04-2_amd64.tar.zst
```

- [ ] **Step 2: Create the LXC**

```bash
pct create 202 local:vztmpl/ubuntu-24.04-standard_24.04-2_amd64.tar.zst \
  --hostname opencti \
  --memory 10240 \
  --swap 1024 \
  --cores 4 \
  --net0 name=eth0,bridge=vmbr0,ip=10.10.30.26/24,gw=10.10.30.1 \
  --rootfs local-lvm:60 \
  --features nesting=1,keyctl=1 \
  --unprivileged 1 \
  --start 1
```

Note: `nesting=1,keyctl=1` is required for Docker inside LXC.

- [ ] **Step 3: Verify LXC is running**

```bash
pct list
# VMID 202 should show "running"

pct exec 202 -- ping -c 3 10.10.30.1
# Should succeed — VLAN 30 connectivity
```

- [ ] **Step 4: Install Docker inside the LXC**

```bash
pct exec 202 -- bash -c '
apt update && apt install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
apt update && apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
'
```

Verify:

```bash
pct exec 202 -- docker run --rm hello-world
```

### Task 19: Deploy OpenCTI Stack

- [ ] **Step 1: Create directory and Docker Compose file**

```bash
pct exec 202 -- mkdir -p /opt/opencti
```

Create the Docker Compose file. Reference the official OpenCTI Docker deployment guide for the latest recommended compose structure. Key services:

```bash
pct exec 202 -- bash -c 'cat > /opt/opencti/docker-compose.yml << "COMPOSE"
services:
  redis:
    image: redis:7
    restart: always
    mem_limit: 512m

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.17.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms3g -Xmx3g
      - xpack.ml.enabled=false
    restart: always
    mem_limit: 4g
    ulimits:
      memlock:
        soft: -1
        hard: -1

  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: opencti
      MINIO_ROOT_PASSWORD: ${MINIO_PASSWORD}
    restart: always
    mem_limit: 256m

  rabbitmq:
    image: rabbitmq:3-management
    environment:
      RABBITMQ_DEFAULT_USER: opencti
      RABBITMQ_DEFAULT_PASS: ${RABBITMQ_PASSWORD}
    restart: always
    mem_limit: 512m

  opencti:
    image: opencti/platform:latest
    environment:
      - NODE_OPTIONS=--max-old-space-size=2048
      - APP__PORT=8080
      - APP__BASE_URL=http://10.10.30.26:8080
      - APP__ADMIN__EMAIL=admin@opencti.local
      - APP__ADMIN__PASSWORD=${OPENCTI_ADMIN_PASSWORD}
      - APP__ADMIN__TOKEN=${OPENCTI_ADMIN_TOKEN}
      - REDIS__HOSTNAME=redis
      - ELASTICSEARCH__URL=http://elasticsearch:9200
      - MINIO__ENDPOINT=minio
      - MINIO__PORT=9000
      - MINIO__USE_SSL=false
      - MINIO__ACCESS_KEY=opencti
      - MINIO__SECRET_KEY=${MINIO_PASSWORD}
      - RABBITMQ__HOSTNAME=rabbitmq
      - RABBITMQ__PORT=5672
      - RABBITMQ__USERNAME=opencti
      - RABBITMQ__PASSWORD=${RABBITMQ_PASSWORD}
    ports:
      - "8080:8080"
    restart: always
    mem_limit: 2g
    depends_on:
      - redis
      - elasticsearch
      - minio
      - rabbitmq

  worker:
    image: opencti/worker:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
    restart: always
    mem_limit: 768m
    deploy:
      replicas: 2
    depends_on:
      - opencti
COMPOSE'
```

**IMPORTANT:** Replace all `changeme-*` passwords with real values. Store them securely. The `APP__ADMIN__TOKEN` becomes the `$opencti_api_key` for Shuffle.

- [ ] **Step 2: Create .env file with real credentials**

```bash
pct exec 202 -- bash -c '
OPENCTI_TOKEN=$(openssl rand -hex 32)
OPENCTI_PASS=$(openssl rand -base64 16)
MINIO_PASS=$(openssl rand -base64 16)
RABBIT_PASS=$(openssl rand -base64 16)

cat > /opt/opencti/.env << ENV
OPENCTI_ADMIN_TOKEN=${OPENCTI_TOKEN}
OPENCTI_ADMIN_PASSWORD=${OPENCTI_PASS}
MINIO_PASSWORD=${MINIO_PASS}
RABBITMQ_PASSWORD=${RABBIT_PASS}
ENV
chmod 600 /opt/opencti/.env

echo "=== RECORD THESE ==="
echo "OpenCTI Admin Token: ${OPENCTI_TOKEN}"
echo "OpenCTI Admin Password: ${OPENCTI_PASS}"
echo "===================="
'
```

**IMPORTANT:** Record the `OPENCTI_ADMIN_TOKEN` — this becomes the `$opencti_api_key` Shuffle workflow variable. The compose file references all passwords via `${VAR}` from this `.env` file.

- [ ] **Step 3: Start OpenCTI**

```bash
pct exec 202 -- bash -c 'cd /opt/opencti && docker compose up -d'
```

Wait 3-5 minutes for first-time initialization (ES indexing, platform bootstrap).

- [ ] **Step 4: Verify OpenCTI is running**

```bash
pct exec 202 -- docker compose -f /opt/opencti/docker-compose.yml ps
```

Expected: All services running.

```bash
curl -s http://10.10.30.26:8080/graphql -H "Authorization: Bearer <OPENCTI_ADMIN_TOKEN>" -H "Content-Type: application/json" -d '{"query": "{ about { version } }"}'
```

Expected: JSON with OpenCTI version.

- [ ] **Step 5: Login to OpenCTI web UI**

Navigate to `http://10.10.30.26:8080`. Login with `admin@opencti.local` and the admin password set in the compose file.

### Task 20: Configure OpenCTI Connectors

- [ ] **Step 1: Add connector services to Docker Compose**

Add the 5 connectors to `/opt/opencti/docker-compose.yml`:

```yaml
  connector-mitre:
    image: opencti/connector-mitre:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=<OPENCTI_ADMIN_TOKEN>
      - CONNECTOR_ID=<generate-uuid>
      - CONNECTOR_NAME=MITRE ATT&CK
      - CONNECTOR_SCOPE=marking-definition,identity,attack-pattern,course-of-action,intrusion-set,campaign,malware,tool,report,vulnerability,external-reference,relationship
      - CONNECTOR_CONFIDENCE_LEVEL=75
      - CONNECTOR_UPDATE_EXISTING_DATA=true
      - CONNECTOR_RUN_AND_TERMINATE=false
      - MITRE_INTERVAL=86400  # daily
    restart: always
    mem_limit: 256m

  connector-cve:
    image: opencti/connector-cve:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=<OPENCTI_ADMIN_TOKEN>
      - CONNECTOR_ID=<generate-uuid>
      - CONNECTOR_NAME=CVE (NVD)
      - CONNECTOR_SCOPE=vulnerability
      - CONNECTOR_CONFIDENCE_LEVEL=75
      - CONNECTOR_UPDATE_EXISTING_DATA=true
      - CVE_INTERVAL=86400  # daily
    restart: always
    mem_limit: 256m

  connector-abuseipdb:
    image: opencti/connector-abuseipdb:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=<OPENCTI_ADMIN_TOKEN>
      - CONNECTOR_ID=<generate-uuid>
      - CONNECTOR_NAME=AbuseIPDB
      - CONNECTOR_SCOPE=indicator
      - CONNECTOR_CONFIDENCE_LEVEL=70
      - ABUSEIPDB_API_KEY=<ABUSEIPDB_KEY>
    restart: always
    mem_limit: 128m

  connector-alienvault:
    image: opencti/connector-alienvault:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=<OPENCTI_ADMIN_TOKEN>
      - CONNECTOR_ID=<generate-uuid>
      - CONNECTOR_NAME=AlienVault OTX
      - CONNECTOR_SCOPE=indicator,report
      - CONNECTOR_CONFIDENCE_LEVEL=60
      - ALIENVAULT_BASE_URL=https://otx.alienvault.com
      - ALIENVAULT_API_KEY=<OTX_API_KEY>
      - ALIENVAULT_INTERVAL=21600  # 6 hours
    restart: always
    mem_limit: 256m

  connector-cisa-kev:
    image: opencti/connector-cisa-known-exploited-vulnerabilities:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=<OPENCTI_ADMIN_TOKEN>
      - CONNECTOR_ID=<generate-uuid>
      - CONNECTOR_NAME=CISA KEV
      - CONNECTOR_SCOPE=vulnerability
      - CONNECTOR_CONFIDENCE_LEVEL=90
      - CONNECTOR_UPDATE_EXISTING_DATA=true
      - CISA_INTERVAL=86400  # daily
    restart: always
    mem_limit: 128m
```

Generate UUIDs for each connector:

```bash
for i in {1..5}; do uuidgen; done
```

- [ ] **Step 2: Restart with connectors**

```bash
pct exec 202 -- bash -c 'cd /opt/opencti && docker compose up -d'
```

- [ ] **Step 3: Verify connectors in OpenCTI UI**

Navigate to Data → Connectors in the OpenCTI web UI. All 5 connectors should show as registered and running. MITRE ATT&CK should begin importing within minutes.

- [ ] **Step 4: Wait for initial import and verify**

After ~30 minutes, verify data is populated:

```bash
curl -s http://10.10.30.26:8080/graphql -H "Authorization: Bearer <OPENCTI_ADMIN_TOKEN>" -H "Content-Type: application/json" -d '{"query": "{ stixCoreObjects { edges { node { entity_type } } pageInfo { globalCount } } }"}'
```

Expected: Non-zero globalCount showing imported STIX objects.

### Task 21: OpenCTI ↔ SIEM Integration (IOC Push)

- [ ] **Step 1: Set up IOC push to Wazuh CDB lists**

This requires a script or connector that exports IOC indicators from OpenCTI and writes them to Wazuh CDB list format on brisket.

Create a cron script on brisket:

```bash
ssh bchaplow@10.10.20.30
cat > ~/opencti-ioc-sync.py << 'PYTHON'
#!/usr/bin/env python3
"""Sync OpenCTI IOCs to Wazuh CDB lists for automatic alert matching."""
import requests
import json
import os

OPENCTI_URL = "http://10.10.30.26:8080/graphql"
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN", "<OPENCTI_ADMIN_TOKEN>")
WAZUH_CDB_DIR = "/var/ossec/etc/lists"

headers = {
    "Authorization": f"Bearer {OPENCTI_TOKEN}",
    "Content-Type": "application/json"
}

# Query malicious IPs
query = '''
{
  indicators(
    filters: {
      mode: and
      filters: [
        { key: "pattern_type", values: ["stix"] }
        { key: "x_opencti_main_observable_type", values: ["IPv4-Addr"] }
      ]
    }
    first: 10000
  ) {
    edges {
      node {
        name
        x_opencti_score
      }
    }
  }
}
'''

resp = requests.post(OPENCTI_URL, json={"query": query}, headers=headers)
data = resp.json()

# Write to CDB list format: key:value
ips = []
for edge in data.get("data", {}).get("indicators", {}).get("edges", []):
    ip = edge["node"]["name"]
    score = edge["node"].get("x_opencti_score", 0)
    if score and score >= 50:
        ips.append(f"{ip}:threat_intel")

with open(f"{WAZUH_CDB_DIR}/opencti-threat-ips", "w") as f:
    f.write("\n".join(ips))

print(f"Synced {len(ips)} threat IPs to Wazuh CDB list")
PYTHON
chmod +x ~/opencti-ioc-sync.py
```

Add to crontab on brisket:

```bash
crontab -e
```

```
# OpenCTI IOC sync to Wazuh CDB lists - every 6 hours
0 */6 * * * /usr/bin/python3 /home/bchaplow/opencti-ioc-sync.py >> /home/bchaplow/opencti-ioc-sync.log 2>&1
```

- [ ] **Step 2: Register CDB list in Wazuh manager config**

SSH to brisket and edit the Wazuh manager ossec.conf (inside the Docker container):

```bash
ssh bchaplow@10.10.20.30
docker exec -it single-node-wazuh.manager-1 bash

# Add the CDB list declaration inside the <ruleset> block of ossec.conf
# Find the <ruleset> section in /var/ossec/etc/ossec.conf and add:
```

```xml
<ruleset>
  ...existing entries...
  <list>etc/lists/opencti-threat-ips</list>
</ruleset>
```

- [ ] **Step 3: Create Wazuh CDB list rule**

Add a custom Wazuh rule in `/var/ossec/etc/rules/local_rules.xml` on brisket (inside the manager container):

```bash
docker exec -it single-node-wazuh.manager-1 bash
# Edit /var/ossec/etc/rules/local_rules.xml and add:
```

```xml
<group name="threat_intel,">
  <rule id="100200" level="12">
    <if_sid>5700</if_sid>
    <list field="srcip" lookup="match_key">etc/lists/opencti-threat-ips</list>
    <description>Connection from OpenCTI threat intelligence IP: $(srcip)</description>
    <group>threat_intel,</group>
  </rule>
</group>
```

Restart Wazuh manager:

```bash
docker restart single-node-wazuh.manager-1
```

Verify the rule loaded:

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
# Paste a test syslog line with a known IOC IP to confirm matching
```

- [ ] **Step 4: Set up threat intel index push to haccp ES**

Use OpenCTI's built-in stream and Elastic connector to push indicators to haccp ES for Elastic Security threat indicator match rules.

In OpenCTI web UI (`http://10.10.30.26:8080`):

1. Navigate to Data → Sharing → Streams
2. Create a new live stream: Name "Elastic Threat Intel", filter for entity type = "Indicator"
3. Record the stream ID from the URL

Add the Elastic connector to the compose file on the OpenCTI LXC:

```yaml
  connector-elastic:
    image: opencti/connector-elasticsearch:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=<generate-uuid>
      - CONNECTOR_NAME=Elastic Threat Intel
      - CONNECTOR_SCOPE=indicator
      - ELASTICSEARCH_URL=https://10.10.30.25:9200
      - ELASTICSEARCH_USERNAME=elastic
      - ELASTICSEARCH_PASSWORD=<PLATFORM_PASSWORD>
      - ELASTICSEARCH_SSL_VERIFY=false
      - ELASTICSEARCH_INDEX=opencti-threat-intel
    restart: always
    mem_limit: 256m
```

```bash
pct exec 202 -- bash -c 'cd /opt/opencti && docker compose up -d'
```

Then in haccp Kibana, create an Elastic Security "Indicator Match" rule that correlates events against the `opencti-threat-intel` index.

### Task 22: OpenCTI ↔ Shuffle Integration

- [ ] **Step 1: Add Shuffle workflow variables**

In Shuffle UI (`https://10.10.20.30:3443`), add workflow variables:
- `$opencti_url` = `http://10.10.30.26:8080`
- `$opencti_api_key` = `<OPENCTI_ADMIN_TOKEN>`

- [ ] **Step 2: Update Shuffle WF1 to query OpenCTI**

In WF1, add an HTTP action after the AbuseIPDB lookup that queries OpenCTI for threat context:

**HTTP Action:**
- Method: POST
- URL: `$opencti_url/graphql`
- Headers: `Authorization: Bearer $opencti_api_key`, `Content-Type: application/json`
- Body:

```json
{
  "query": "{ stixCoreObjects(search: \"$srcip\") { edges { node { entity_type x_opencti_score ... on Indicator { name pattern description } } } } }"
}
```

Feed the response into the TheHive case creation action to include threat intel context.

- [ ] **Step 3: Test WF1 with OpenCTI enrichment**

Trigger WF1 manually with a known IOC IP. Verify:
- AbuseIPDB lookup succeeds
- ML Scorer returns a score
- OpenCTI query returns threat context (if the IP exists in intel)
- TheHive case includes OpenCTI enrichment data
- Discord notification fires

### Task 23: OpenCTI ↔ TheHive Connector

- [ ] **Step 1: Configure TheHive connector in OpenCTI**

Add the TheHive connector to the Docker Compose:

```yaml
  connector-thehive:
    image: opencti/connector-thehive:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=<OPENCTI_ADMIN_TOKEN>
      - CONNECTOR_ID=<generate-uuid>
      - CONNECTOR_NAME=TheHive
      - CONNECTOR_SCOPE=thehive
      - THEHIVE_URL=http://10.10.30.22:9000
      - THEHIVE_API_KEY=<THEHIVE_API_KEY>
    restart: always
    mem_limit: 128m
```

```bash
pct exec 202 -- bash -c 'cd /opt/opencti && docker compose up -d'
```

- [ ] **Step 2: Verify connector is registered**

Check OpenCTI UI → Data → Connectors. TheHive connector should appear and show as active.

- [ ] **Step 3: Test observable sharing**

Create a test indicator in OpenCTI. Verify it appears as an observable in TheHive, or create a case in TheHive and verify OpenCTI enrichment data is available.

---

## Chunk 5: Phase E — Operational Practices + Elastic ML + Documentation

### Task 24: Configure Elastic ML Anomaly Jobs

- [ ] **Step 1: Create auth anomaly detection job**

In haccp Kibana (`https://10.10.30.25:5601`) → Machine Learning → Anomaly Detection → Create Job.

**Job: auth-anomalies**
- Data view: Fleet agent data from DC01/WS01 (Windows Security events)
- Filter: `event.code: (4624 OR 4625 OR 4672)`
- Bucket span: 15 minutes
- Detectors:
  - `high_count` by `event.outcome` partitioned by `user.name`
  - `rare` by `source.ip` partitioned by `user.name`
- Influencers: `user.name`, `source.ip`, `event.outcome`

- [ ] **Step 2: Create network traffic volume anomaly job**

**Job: network-volume-anomalies**
- Data view: `arkime_sessions3-*`
- Bucket span: 15 minutes
- Detectors:
  - `high_sum(network.bytes)` partitioned by `source.ip`
  - `high_count` partitioned by `destination.ip`
- Influencers: `source.ip`, `destination.ip`, `network.bytes`

- [ ] **Step 3: Start both jobs and verify**

Start both jobs. After 1-2 hours, check ML Explorer in Kibana for initial results. Jobs need time to build baseline models before detecting anomalies.

### Task 25: Set Up Sigma Rules Workflow

- [ ] **Step 1: Create directory structure in repo**

```bash
cd /c/Projects/homelab-soc-portfolio
mkdir -p sigma-rules/{rules,converted/wazuh,converted/elastic}
```

- [ ] **Step 2: Create README for Sigma workflow**

Create `sigma-rules/README.md` documenting:
- How to write Sigma rules (reference: sigmahq.io)
- How to convert to Wazuh: `sigma-cli convert -t wazuh -p wazuh rules/<rule>.yml`
- How to convert to Elastic: `sigma-cli convert -t elasticsearch -p ecs-windows rules/<rule>.yml`
- How to deploy converted rules to each platform

- [ ] **Step 3: Create an example Sigma rule**

Create `sigma-rules/rules/win_bruteforce_logon_failure.yml`:

```yaml
title: Windows Brute Force Logon Failures
id: <generate-uuid>
status: experimental
description: Detects multiple failed logon attempts indicating brute force activity
author: Brian Chaplow
date: 2026/03/14
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection | count() by SourceIP > 10
  timeframe: 5m
level: high
tags:
  - attack.credential_access
  - attack.t1110
```

- [ ] **Step 4: Convert and deploy the example rule**

Convert to both formats and document the output. Deploy the Wazuh version to brisket and the Elastic version to haccp to demonstrate the dual-SIEM workflow.

### Task 26: Set Up YARA Rules Workflow

- [ ] **Step 1: Create directory structure in repo**

```bash
mkdir -p yara-rules/{rules,docs}
```

- [ ] **Step 2: Create an example YARA rule**

Create `yara-rules/rules/suspicious_powershell.yar`:

```yara
rule Suspicious_PowerShell_Encoded_Command
{
    meta:
        description = "Detects encoded PowerShell commands often used in malware"
        author = "Brian Chaplow"
        date = "2026-03-14"
        mitre_attack = "T1059.001"

    strings:
        $enc1 = "-EncodedCommand" ascii nocase
        $enc2 = "-enc " ascii nocase
        $b64 = /[A-Za-z0-9+\/]{50,}={0,2}/ ascii

    condition:
        ($enc1 or $enc2) and $b64
}
```

- [ ] **Step 3: Configure Velociraptor YARA hunt**

In Velociraptor GUI (`https://10.10.20.30:8889`), create a new artifact or use the built-in `Windows.Detection.Yara.NTFS` artifact. Upload the YARA rule and configure a hunt targeting Windows endpoints (DC01, WS01).

- [ ] **Step 4: Document Cortex YARA analyzer setup**

Note for the Cortex YARA analyzer on pitcrew (TheHive LXC 200): the analyzer is already one of the 5 installed analyzers. Document how to submit files/hashes from TheHive cases for YARA scanning.

- [ ] **Step 5: Import YARA rules as STIX indicators in OpenCTI**

In OpenCTI web UI, navigate to Observations → Indicators → Create. Create a YARA indicator:
- Pattern type: `yara`
- Pattern: paste the YARA rule content
- Name: `Suspicious_PowerShell_Encoded_Command`
- Link to MITRE ATT&CK technique T1059.001 (already imported via ATT&CK connector)

This connects YARA detections to the broader threat intel graph in OpenCTI.

### Task 27: Update Portfolio Documentation

- [ ] **Step 1: Update network-topology.md**

Update `docs/network-topology.md` to reflect:
- haccp added to Host Inventory (VLAN 30 section)
- OpenCTI LXC added to pitcrew section
- InfluxDB/Grafana/Telegraf removed from smokehouse section
- Telegraf removed from pitcrew and smoker
- MokerLink port map updated (TE8 VLAN change, TE11 added)
- Physical topology Mermaid diagram updated
- Logical topology Mermaid diagram updated (add OpenCTI, Arkime, remove v2 metrics)
- Data flow narrative updated

- [ ] **Step 2: Update architecture.md**

Update `docs/architecture.md` to reflect:
- haccp as new Detection & PCAP host
- OpenCTI as threat intelligence platform
- Threat intel pipeline (new section)
- Arkime packet capture (new section)
- Sigma/YARA operational practices (new section)
- v2 metrics stack removed

- [ ] **Step 3: Update phases.md or create new phase**

Add Phase 12 (or equivalent) documenting the infrastructure redesign as a completed phase, following the convention of the existing 11 phases.

- [ ] **Step 4: Commit all documentation changes**

```bash
cd /c/Projects/homelab-soc-portfolio
git add docs/ sigma-rules/ yara-rules/
git commit -m "Phase 12: Infrastructure redesign — haccp + OpenCTI + consolidation

- Added haccp bare metal node (ELK 8.17 + Arkime PCAP)
- Added OpenCTI threat intelligence platform on pitcrew
- Migrated ELK from pitcrew LXC 201 to haccp
- Decommissioned v2 metrics stack (InfluxDB/Telegraf/Grafana)
- Re-enabled Cloudflare auto-blocking
- Added Sigma and YARA operational practices
- Updated network topology and architecture docs"
```
