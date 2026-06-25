# Self-Deployment Guide — realtime-packet-sniff IDS

> Step-by-step instructions to install and run the full IDS stack on a fresh Ubuntu server,  
> from dependency setup through to Grafana displaying live attack data.

**Tested on:** Ubuntu 22.04 / 24.04 LTS (x86-64)  
**Estimated setup time:** 45 – 90 minutes  
**Version:** v0.3.0

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Architecture Overview](#2-architecture-overview)
3. [Step 1 — Prepare the System](#step-1--prepare-the-system)
4. [Step 2 — Python & Clone Repo](#step-2--python--clone-repo)
5. [Step 3 — Apache Kafka (KRaft)](#step-3--apache-kafka-kraft)
6. [Step 4 — ClickHouse](#step-4--clickhouse)
7. [Step 5 — Grafana](#step-5--grafana)
8. [Step 6 — Argus & Zeek](#step-6--argus--zeek)
9. [Step 7 — Configure the Pipeline](#step-7--configure-the-pipeline)
10. [Step 8 — Initialise the ClickHouse Schema](#step-8--initialise-the-clickhouse-schema)
11. [Step 9 — Install systemd Services](#step-9--install-systemd-services)
12. [Step 10 — Start & Verify](#step-10--start--verify)
13. [Quick Install (capture tool only)](#quick-install-capture-tool-only)
14. [Day-to-Day Operations](#day-to-day-operations)
15. [Troubleshooting](#troubleshooting)

---

## 1. System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8 GB+ |
| Disk | 20 GB | 50 GB+ (Kafka + ClickHouse long-term storage) |
| OS | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| Python | 3.8+ | 3.10+ |
| Java | 11+ (for Kafka) | 17 |
| Network interface | 1 NIC | 2 NICs (1 mgmt + 1 SPAN/mirror) |

> **Note:** Root or `sudo` access is required throughout.  
> The default interface in this guide is `ens33` — replace it with your actual interface name.

---

## 2. Architecture Overview

The system has **5 components** running in a chain:

```
NIC (ens33)
    │ libpcap / scapy
    ▼
[sniff-producer]          ← Python, systemd service (root)
    │ ~60 s pcap blob
    ▼
[Kafka topic: raw_pcap_segments]   ← Apache Kafka KRaft
    │
    ▼
[ec-consumer]             ← Python, systemd service (non-root)
    │ Argus + Zeek → UNSW-NB15 feature extraction
    │ auto_pipeline.py → 7 filters + DoS classifier
    ▼
[ClickHouse]              ← stores classified flow records
    │
    ▼
[Grafana]                 ← real-time attack visualisation
```

**Detailed data flow:**
1. `sniff-producer` captures packets from the NIC, buffers ~60 seconds, packs them into a blob and publishes to Kafka.
2. `ec-consumer` reads the blob from Kafka and writes a temporary `.pcap` file to `/dev/shm`.
3. `auto_pipeline.py` processes the `.pcap` through 4 stages:
   - **Step 1/4:** `extractor.py` (Argus + Zeek) → raw UNSW-NB15 feature CSV.
   - **Step 2/4:** `add_features.py` → adds 49 DoS-specific columns.
   - **Step 3/4:** 7 per-family filters → 7 labelled CSV files.
   - **Step 4/4:** `dos_classifier.py` → detailed SYN / UDP / ICMP Flood scoring.
4. `ClickHouseSink` writes results to 7 `flows_<family>` tables + the `pipeline_runs` audit table.
5. Grafana reads ClickHouse and renders the dashboard.

---

## Step 1 — Prepare the System

### 1.1 Update the system and install base tools

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y \
    curl wget git unzip \
    build-essential \
    libpcap-dev \
    tcpdump tcpreplay \
    python3 python3-pip python3-venv \
    openjdk-17-jre-headless
```

> - `curl wget git unzip` — download tools and source control
> - `build-essential` — C/C++ compiler toolchain (required by some Python packages)
> - `libpcap-dev` — raw packet capture library, required by scapy
> - `tcpdump tcpreplay` — traffic inspection and replay tools
> - `python3 python3-pip python3-venv` — Python runtime and virtual environment support
> - `openjdk-17-jre-headless` — Java runtime required by Kafka

### 1.2 Identify your network interface

```bash
ip link show
# Note the name of the interface you want to sniff on, e.g. ens33, eth0, enp3s0
```

> If you are running on a VM (VMware / VirtualBox), set the target NIC to  
> **Promiscuous Mode** so it can capture all traffic on the segment, not just its own.

---

## Step 2 — Python & Clone Repo

### 2.1 Clone the repository

```bash
git clone https://github.com/ntu168108/realtime-packet-sniff.git
cd realtime-packet-sniff
```

### 2.2 Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

> From this point on, **always activate the venv** before running Python commands:  
> `source /path/to/realtime-packet-sniff/.venv/bin/activate`

### 2.3 Install Python dependencies

```bash
# Capture tool (scapy only)
pip install -r requirements.txt

# Full IDS pipeline (Kafka, ClickHouse, pandas, …)
pip install -r requirements-integration.txt
```

**Key packages:**

| Package | Version | Used for |
|---------|---------|----------|
| `scapy` | ≥2.5.0 | Packet capture via libpcap |
| `kafka-python-ng` | 2.2.3 | Kafka producer / consumer |
| `clickhouse-driver` | 0.2.9 | Inserting data into ClickHouse |
| `pandas` | 2.2.2 | CSV processing, scoring |
| `numpy` | 1.26.4 | Vectorized scoring |
| `pyyaml` | 6.0.1 | Config file parsing |

### 2.4 Verify the installation

```bash
python3 -c "from core import capture; from cli import app; print('core & cli OK')"
python3 -c "from integration import ec_consumer, clickhouse_sink; print('integration OK')"
```

---

## Step 3 — Apache Kafka (KRaft)

> This setup uses Kafka in **KRaft mode** — no ZooKeeper required.

### 3.1 Download and extract Kafka

```bash
KAFKA_VERSION="4.3.1"
wget https://downloads.apache.org/kafka/${KAFKA_VERSION}/kafka_2.13-${KAFKA_VERSION}.tgz
sudo tar -xzf kafka_2.13-${KAFKA_VERSION}.tgz -C /opt/
sudo ln -sf /opt/kafka_2.13-${KAFKA_VERSION} /opt/kafka
```

> - `wget ...tgz` — download the latest Kafka release
> - `tar -xzf ... -C /opt/` — extract into `/opt/`
> - `ln -sf` — create a `/opt/kafka` symlink pointing at the versioned directory (makes future upgrades easier)

### 3.2 Apply the Kafka configuration

```bash
sudo cp deploy/kafka/server.properties /opt/kafka/config/kraft/server.properties
```

> Copies the pre-configured KRaft `server.properties` from the repo over Kafka's default config.

Key settings in `server.properties`:

```properties
process.roles=broker,controller       # KRaft mode — no ZooKeeper
node.id=1
controller.quorum.voters=1@localhost:9093
listeners=PLAINTEXT://localhost:9092,CONTROLLER://localhost:9093
advertised.listeners=PLAINTEXT://localhost:9092
log.dirs=/var/lib/kafka-logs
log.retention.ms=3600000              # keep data for 1 hour (adjust as needed)
log.retention.bytes=2147483648        # or 2 GiB per partition
```

### 3.3 Format storage and create the topic

```bash
sudo mkdir -p /var/lib/kafka-logs
sudo chown $USER:$USER /var/lib/kafka-logs

# Generate a cluster ID and format storage
KAFKA_CLUSTER_ID=$(/opt/kafka/bin/kafka-storage.sh random-uuid)
/opt/kafka/bin/kafka-storage.sh format \
    -t $KAFKA_CLUSTER_ID \
    -c /opt/kafka/config/kraft/server.properties


# Start Kafka temporarily to create the topic
/opt/kafka/bin/kafka-server-start.sh /opt/kafka/config/kraft/server.properties &
sleep 10

# Create the topic
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
    --create --topic raw_pcap_segments \
    --partitions 1 \
    --replication-factor 1

# Verify
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list

# Stop Kafka — systemd will manage it from now on
/opt/kafka/bin/kafka-server-stop.sh
```

> - `random-uuid` — generates a unique cluster ID
> - `format` — initialises the storage directory with that cluster ID (one-time setup only)

---

## Step 4 — ClickHouse

### 4.1 Install via apt

```bash
sudo apt-get install -y apt-transport-https ca-certificates
curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | \
    sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] \
    https://packages.clickhouse.com/deb stable main" | \
    sudo tee /etc/apt/sources.list.d/clickhouse.list

sudo apt-get update
sudo apt-get install -y clickhouse-server clickhouse-client
```

> - `apt-transport-https ca-certificates` — enables apt to download packages over HTTPS
> - `gpg --dearmor` — adds the ClickHouse GPG signing key so apt can verify packages
> - `tee /etc/apt/sources.list.d/clickhouse.list` — registers the ClickHouse apt repository
> - `clickhouse-server` — the main database service
> - `clickhouse-client` — CLI for running queries and verifying the install

### 4.2 Start ClickHouse

```bash
sudo systemctl enable clickhouse-server
sudo systemctl start clickhouse-server
```

### 4.3 Verify

```bash
clickhouse-client --query "SELECT version()"
# Expected: a version string such as 24.3.1.2672
```

---

## Step 5 — Grafana

### 5.1 Install via apt

```bash
sudo apt-get install -y apt-transport-https software-properties-common
wget -q -O - https://apt.grafana.com/gpg.key | \
    sudo gpg --dearmor -o /usr/share/keyrings/grafana.key

echo "deb [signed-by=/usr/share/keyrings/grafana.key] \
    https://apt.grafana.com stable main" | \
    sudo tee /etc/apt/sources.list.d/grafana.list

sudo apt-get update
sudo apt-get install -y grafana
```

> - `gpg --dearmor` — adds the Grafana GPG signing key
> - `tee /etc/apt/sources.list.d/grafana.list` — registers the Grafana apt repository

### 5.2 Install the ClickHouse data source plugin

```bash
sudo grafana-cli plugins install grafana-clickhouse-datasource
```

### 5.3 Provision the data source and dashboard automatically

```bash
sudo cp deploy/grafana/datasource.yaml  /etc/grafana/provisioning/datasources/
sudo cp deploy/grafana/dashboards.yaml  /etc/grafana/provisioning/dashboards/
sudo cp deploy/grafana/dashboard.json   /var/lib/grafana/dashboards/


sudo systemctl enable grafana-server
sudo systemctl start grafana-server
```

> - `datasource.yaml` — auto-configures the ClickHouse connection on Grafana startup
> - `dashboards.yaml` — tells Grafana where to find the dashboard files
> - `dashboard.json` — the IDS pipeline dashboard

> **Access Grafana:** `http://<server-ip>:3000`  
> Default credentials: `admin` / `admin` (change on first login)  
> Dashboard: **IDS → "SNIFF IDS Pipeline"**

---

## Step 6 — Argus & Zeek

The feature extraction stage uses **Argus** (flow records) and **Zeek** (deep packet inspection).

### 6.1 Install Argus

```bash
sudo apt-get install -y argus-server argus-client


argus -V && ra -V
```

> - `argus-server` — generates flow records from pcap files
> - `argus-client` (`ra`) — tool for reading and querying flow records

> If the apt package is not available, build from source:
> ```bash

```

> wget https://openargus.org/download/argus-3.0.8.tar.gz
> tar xzf argus-3.0.8.tar.gz && cd argus-3.0.8
> ./configure && make && sudo make install
> 

### 6.2 Install Zeek

```bash
# Quick install via package script
sudo bash -c "$(wget -qO - https://raw.githubusercontent.com/zeek/zeek-docs/master/scripts/zeek-setup.sh)"

# Or via apt if available
sudo apt-get install -y zeek

zeek --version
```

If Zeek lands in `/opt/zeek`, add it to `PATH`:

```bash
sudo ln -sf /opt/zeek/bin/zeek    /usr/local/bin/zeek
sudo ln -sf /opt/zeek/bin/zeekctl /usr/local/bin/zeekctl
```

### 6.3 Confirm both tools are reachable

```bash
which argus ra zeek
zeek --version
```

---

## Step 7 — Configure the Pipeline

### 7.1 Create `config.yaml`

```bash
cp config.yaml.example config.yaml
```

Edit the following keys:

```yaml
capture:
  interface: ens33          # ← your actual interface name
  bpf: "not port 22"        # exclude SSH to reduce noise
  keep_local_pcap: false    # set to true to keep pcap files after processing

kafka:
  bootstrap: localhost:9092
  topic: raw_pcap_segments
  segment_seconds: 60       # flush every 60 seconds …
  segment_max_bytes: 67108864  # … or at 64 MiB, whichever comes first

clickhouse:
  host: localhost
  port: 9000
  database: network_ids
  batch_size: 10000         # rows per INSERT batch
```

### 7.2 Check the Extraction-and-classification path

The pipeline auto-discovers `Extraction-and-classification/` relative to the repo root in most layouts. If you clone to a non-standard location, set:

```bash
export NB15_EC=/path/to/Extraction-and-classification
```

---

## Step 8 — Initialise the ClickHouse Schema

```bash
clickhouse-client --multiquery < sql/clickhouse_init.sql

# Verify tables
clickhouse-client --query "SHOW TABLES FROM network_ids"
```

Expected output:

```
flows_all
flows_analysis
flows_dos
flows_exploits
flows_fuzzers
flows_generic
flows_reconnaissance
flows_shellcode
pipeline_runs
```

**Schema notes:**
- `flows_<family>` use `ReplacingMergeTree` — re-processing the same segment never duplicates rows (idempotent by design).
- `flows_all` is a `Merge` view across all 7 family tables — use it for cross-family queries.
- `pipeline_runs` is a `MergeTree` audit table — one row per consumed segment.
- Default TTL: **14 days** — rows older than that are automatically dropped.

---

## Step 9 — Install systemd Services

### 9.1 Copy the unit files

```bash
sudo cp deploy/systemd/kafka.service           /etc/systemd/system/
sudo cp deploy/systemd/sniff-producer.service  /etc/systemd/system/
sudo cp deploy/systemd/ec-consumer.service     /etc/systemd/system/
```

### 9.2 Patch paths and user to match your environment

```bash
REPO_DIR=$(pwd)

sudo sed -i "s|/home/tu/realtime-packet-sniff|${REPO_DIR}|g" \
    /etc/systemd/system/kafka.service \
    /etc/systemd/system/sniff-producer.service \
    /etc/systemd/system/ec-consumer.service

sudo sed -i "s|User=tu|User=${USER}|g" /etc/systemd/system/ec-consumer.service
```

### 9.3 Unit file reference

**`kafka.service`** — single-broker KRaft:
```ini
[Unit]
Description=Apache Kafka (KRaft)
After=network.target

[Service]
ExecStart=/opt/kafka/bin/kafka-server-start.sh /opt/kafka/config/kraft/server.properties
ExecStop=/opt/kafka/bin/kafka-server-stop.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**`sniff-producer.service`** — capture engine → Kafka (needs root for raw sockets):
```ini
[Unit]
Description=SNIFF Packet Producer
After=network.target kafka.service
Requires=kafka.service

[Service]
WorkingDirectory=/home/tu/realtime-packet-sniff
ExecStart=/home/tu/realtime-packet-sniff/.venv/bin/python -m integration.run_producer
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**`ec-consumer.service`** — Kafka → Argus+Zeek → ClickHouse:
```ini
[Unit]
Description=SNIFF EC Consumer (Extract + Classify)
After=network.target kafka.service clickhouse-server.service
Requires=kafka.service

[Service]
User=tu
WorkingDirectory=/home/tu/realtime-packet-sniff
ExecStart=/home/tu/realtime-packet-sniff/.venv/bin/python -m integration.ec_consumer
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 9.4 Reload systemd and enable services

```bash
sudo systemctl daemon-reload
sudo systemctl enable kafka sniff-producer ec-consumer
```

---

## Step 10 — Start & Verify

### 10.1 Start services in order

```bash
# Kafka must come first
sudo systemctl start kafka
sleep 5
sudo systemctl status kafka

# Then the producer
sudo systemctl start sniff-producer
sleep 3
sudo systemctl status sniff-producer

# Finally the consumer (ClickHouse must already be up)
sudo systemctl start ec-consumer
sudo systemctl status ec-consumer
```

### 10.2 Check the full stack

```bash
sudo systemctl is-active kafka sniff-producer ec-consumer clickhouse-server grafana-server
# Expected: active active active active active

# Follow ec-consumer logs live
sudo journalctl -u ec-consumer -f
```

### 10.3 Send test traffic

```bash
# Capture 30 seconds of live traffic
sudo tcpdump -i ens33 -w /tmp/test.pcap -G 30 -W 1

# Or replay an existing pcap
sudo tcpreplay -i ens33 --mbps=10 /path/to/sample.pcap
```

After ~90 seconds (60 s segment window + processing time), check for data:

```bash
# Kafka: how many messages have been published
/opt/kafka/bin/kafka-run-class.sh kafka.tools.GetOffsetShell \
    --broker-list localhost:9092 --topic raw_pcap_segments

# ClickHouse: total rows ingested
clickhouse-client --query "SELECT count() FROM network_ids.flows_all"

# Breakdown by attack family
clickhouse-client --query \
    "SELECT attack_family, count() AS cnt
     FROM network_ids.flows_all
     WHERE is_attack = 1
     GROUP BY attack_family
     ORDER BY cnt DESC"

# Pipeline health — last 5 runs
clickhouse-client --query \
    "SELECT started_at, status, total_flows, duration_sec, error_msg
     FROM network_ids.pipeline_runs
     ORDER BY started_at DESC LIMIT 5"
```

### 10.4 Open Grafana

Navigate to `http://<server-ip>:3000` → **Dashboards → IDS → "SNIFF IDS Pipeline"**.  
If the dashboard is empty, wait another minute and click **Refresh**.

---

## Quick Install (capture tool only)

If you only need the interactive capture tool (TUI / daemon / live NDJSON stream) without Kafka, ClickHouse, or Grafana:

```bash
# One-liner
curl -fsSL https://raw.githubusercontent.com/ntu168108/realtime-packet-sniff/main/install.sh -o /tmp/install.sh && sudo bash /tmp/install.sh --verbose

# Or manually
git clone https://github.com/ntu168108/realtime-packet-sniff.git
cd realtime-packet-sniff
python3 -m venv .venv && source .venv/bin/activate
pip install .

# Usage
sudo sniff                          # interactive menu
sudo sniff -i ens33                 # capture on ens33
sudo sniff -i ens33 --live | jq .   # live NDJSON stream
sudo sniff -i ens33 -d              # background daemon
sudo sniff --status                 # daemon status
sudo sniff --stop                   # stop the daemon
```

---

## Day-to-Day Operations

### Start / stop / restart

```bash
sudo systemctl start   kafka sniff-producer ec-consumer
sudo systemctl stop    ec-consumer sniff-producer kafka
sudo systemctl restart ec-consumer   # after a code change
```

### View logs

```bash
sudo journalctl -u ec-consumer -f                            # live tail
sudo journalctl -u ec-consumer --no-pager | grep -E "ERROR|FAILED|segment="
sudo journalctl -u sniff-producer -n 50 --no-pager
```

### Useful ClickHouse queries

```sql
-- Attack distribution by family
SELECT attack_family, count() AS c
FROM network_ids.flows_all
WHERE is_attack = 1
GROUP BY attack_family ORDER BY c DESC;

-- Top 10 attacker IPs
SELECT srcip, count() AS c
FROM network_ids.flows_all
WHERE is_attack = 1
GROUP BY srcip ORDER BY c DESC LIMIT 10;

-- Attack timeline (per minute)
SELECT toStartOfMinute(ts) AS t, attack_family, count() AS c
FROM network_ids.flows_all
WHERE is_attack = 1
GROUP BY t, attack_family ORDER BY t;

-- Pipeline health — last 10 runs
SELECT started_at, status, total_flows, duration_sec, error_msg
FROM network_ids.pipeline_runs
ORDER BY started_at DESC LIMIT 10;
```

### Run the classifier manually

```bash
cd Extraction-and-classification

# Run the full 4-step pipeline on a pcap file
python3 MODULE_AUTO/auto_pipeline.py /path/to/capture.pcap

# Run the DoS classifier standalone
python3 MODULE_PHANLOAI/dos_classifier.py \
    --csv CSV/CSV_Full_feature/capture_dos_features.csv \
    --skip-filter

# Run all unit tests
python3 -m pytest MODULE_PHANLOAI/tests/ -v
```

---

## Troubleshooting

### ❌ `sniff-producer` cannot connect to Kafka

```bash
sudo systemctl status kafka
ss -tlnp | grep 9092
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list
```

### ❌ `ec-consumer` — ClickHouse connection refused

```bash
sudo systemctl status clickhouse-server
ss -tlnp | grep 9000
clickhouse-client --query "SELECT 1"
```

### ❌ Pipeline reports "argus not found" or "zeek not found"

```bash
which argus zeek
# If missing, add to PATH:
export PATH=$PATH:/opt/zeek/bin:/usr/local/bin
sudo ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
```

### ❌ `dos_classifier.py` import error

```bash
cd Extraction-and-classification/MODULE_PHANLOAI
python3 -c "import dos_classifier; print('OK')"
# If pandas is missing:
pip install pandas numpy
```

### ❌ Grafana shows no data

```bash
# 1. Check the data source is provisioned
curl -s -u admin:admin http://localhost:3000/api/datasources | python3 -m json.tool

# 2. Check ClickHouse has rows
clickhouse-client --query "SELECT count() FROM network_ids.flows_all"

# 3. Re-check provisioning files and restart
ls /etc/grafana/provisioning/datasources/
sudo systemctl restart grafana-server
```

### ❌ Reset Kafka completely

```bash
# WARNING: this deletes ALL Kafka data
sudo systemctl stop kafka
sudo rm -rf /var/lib/kafka-logs
KAFKA_CLUSTER_ID=$(/opt/kafka/bin/kafka-storage.sh random-uuid)
/opt/kafka/bin/kafka-storage.sh format \
    -t $KAFKA_CLUSTER_ID \
    -c /opt/kafka/config/kraft/server.properties

sudo systemctl start kafka
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
    --create --topic raw_pcap_segments --partitions 1 --replication-factor 1
```

> - `random-uuid` — generates a unique cluster ID
> - `format` — initialises the storage directory with that cluster ID (one-time setup only)

### ❌ Purge old ClickHouse data manually

```bash
# Delete data older than 7 days from all family tables
for family in dos exploits fuzzers generic analysis reconnaissance shellcode; do
    clickhouse-client --query \
        "ALTER TABLE network_ids.flows_${family} DELETE WHERE ts < now() - INTERVAL 7 DAY"
done

# Or change the TTL permanently (default is 14 days)
for family in dos exploits fuzzers generic analysis reconnaissance shellcode; do
    clickhouse-client --query \
        "ALTER TABLE network_ids.flows_${family} MODIFY TTL toDateTime(ts) + INTERVAL 7 DAY"
done
```

---

## Directory Reference

```
realtime-packet-sniff/
├── sniff.py                    # Capture tool CLI entry point
├── install.sh                  # One-liner installer (capture tool)
├── config.yaml.example         # Config template → copy to config.yaml
├── requirements.txt            # Capture tool deps
├── requirements-integration.txt # Full IDS pipeline deps
├── core/                       # Capture engine (capture, decoder, buffer, …)
├── cli/                        # TUI, daemon, live printer
├── ui/                         # Colour helpers for the TUI
├── modules/                    # Plugin analyzers (port scan, DNS tunnel, beaconing)
├── integration/                # Kafka producer/consumer, ClickHouse sink, schema
├── Extraction-and-classification/
│   ├── MODULE_TRICHXUAT/       # Argus + Zeek → UNSW-NB15 feature extraction
│   ├── MODULE_PHANLOAI/        # 7 filters + dos_classifier + signatures
│   └── MODULE_AUTO/            # Orchestrator: auto_pipeline.py
├── deploy/
│   ├── systemd/                # Unit files: kafka, sniff-producer, ec-consumer
│   ├── kafka/                  # server.properties (KRaft)
│   └── grafana/                # Datasource + dashboard provisioning
├── sql/
│   └── clickhouse_init.sql     # DDL: 7 flows_<family> + flows_all + pipeline_runs
├── tests/integration_tests/    # 36 automated tests
└── docs/
    ├── ARCHITECTURE.md         # Detailed architecture, blob format, CH schema
    └── OPERATIONS.md           # Operations runbook, queries, retention
```

---

*This guide covers v0.3.0 — see the [Releases page](https://github.com/ntu168108/realtime-packet-sniff/releases) for the latest changes.*
