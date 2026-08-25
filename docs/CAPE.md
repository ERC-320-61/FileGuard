# CAPE Dynamic Analysis

## Purpose

CAPE is FileGuard's internal dynamic-analysis layer. It executes eligible quarantined files inside an isolated, disposable Windows guest to observe runtime behavior, and returns that behavioral evidence to enrich analyst review. CAPE is a private, internal capability — not an external submission service — consistent with FileGuard's controlled-data handling requirements.

This document is the source of truth for CAPE's local development lab: what has been built and verified, what remains unverified, the operational lessons learned while building it, and how the local design is intended to carry forward to an eventual AWS deployment without requiring FileGuard's own logic to change.

## Role in FileGuard

FileGuard's intended lifecycle is:

```
Receive → Isolate → Statically Analyze → Decide → Disposition
  → Dynamically Analyze Exceptions → Record → Notify → Investigate → Learn
```

CAPE implements the "Dynamically Analyze Exceptions" stage. Only files that have already been dispositioned to Quarantine by the static OPA policy are eligible for CAPE submission — a `CLEAN` disposition never reaches CAPE. Initial CAPE eligibility is expected to focus on the `SUSPICIOUS` outcome (of the current `MALICIOUS > INCOMPLETE > SUSPICIOUS > CLEAN` precedence); this eligibility policy is not yet implemented in FileGuard application code.

CAPE does not make or override disposition decisions, and does not automatically release a file from Quarantine. Its output is additional evidence for analyst review — the same fail-closed posture already established for static analysis applies here: the absence of interesting dynamic behavior is not proof a file is safe, and CAPE observing something is not proof a file is malicious.

## Current Local Architecture

The local lab exists to prove the integration shape before any AWS work begins:

```
FileGuard → CAPE API → isolated Windows sandbox → behavioral report → (future) FileGuard normalization
```

Verified local topology:

```
Windows physical development host
├── WSL2 / FileGuard development
└── Hyper-V
    └── Ubuntu CAPE VM (FileGuard-CAPE)
        ├── CAPEv2
        ├── MongoDB
        ├── KVM/libvirt
        └── isolated Windows analysis VM (fileguard-win-sandbox)
            └── CAPE agent
```

Hyper-V is specific to this local development machine — it is the local lab's hypervisor, not an architectural requirement of FileGuard. The AWS target uses a nested-virtualization-capable EC2 instance in its place; nothing about FileGuard's own design depends on Hyper-V. CAPEv2 itself is external upstream software, run locally under `/opt/CAPEv2` on the Ubuntu VM. It is not vendored into this repository, the same treatment already applied to Strelka.

## Verified Local Baseline

### CAPE Host

- Hyper-V VM name: `FileGuard-CAPE`
- Ubuntu Server 24.04
- 8 vCPU, 16 GB RAM, 100 GB dynamic VHDX
- Host address on the Hyper-V network: `172.29.176.243`
- Nested virtualization enabled
- CAPE installed under `/opt/CAPEv2`, using KVM/libvirt for the nested Windows analysis guest

### Isolated Network

- Dedicated libvirt network: `cape-isolated`
- Bridge interface: `virbr10`
- CAPE host sandbox-facing address: `192.168.56.1/24`
- No external forwarding — the network intentionally cannot reach anything beyond the CAPE host
- Windows sandbox address: `192.168.56.101/24`, DHCP reservation tied to MAC `52:54:00:46:47:01`
- No default gateway configured inside the Windows guest
- Host-to-guest connectivity has been validated

### Windows Sandbox

- libvirt VM name: `fileguard-win-sandbox`
- Current guest OS: Windows Server 2025 Standard Evaluation (Desktop Experience) — used for plumbing/PoC validation only. CAPE upstream generally recommends supported desktop Windows versions (10/11); Windows Server 2025 is **not** being declared the final production sandbox OS, and the guest may be replaced if behavioral-monitoring compatibility problems appear.
- 4 vCPU, 6144 MB RAM, ~50 GB sparse qcow2 disk (`/var/lib/libvirt/images/fileguard-win-sandbox.qcow2`)

### CAPE Agent

The CAPE agent is installed inside the Windows guest at `C:\CAPE\agent.py`, with a windowless copy at `C:\CAPE\agent.pyw`, running under a 32-bit Python 3.8.10 interpreter (`C:\Python38-32`) — 32-bit was intentionally selected because CAPE recommends an x86 Python interpreter for the guest agent. The agent listens on TCP/8000; the Windows Firewall restricts inbound access on that port to the CAPE host's sandbox-facing address (`192.168.56.1`) only. The agent runs elevated, with autostart configured via a Windows Scheduled Task so it is available immediately after every snapshot revert without manual intervention.

Verified host-to-agent connectivity:

```
curl http://192.168.56.101:8000
```

returned `CAPE Agent`, `version 0.22`, and reported `is_user_admin: true`.

The durable requirement here is not the exact installation steps but the outcome: the guest agent must be elevated, reachable only from the CAPE host, and automatically available the moment the clean sandbox state is restored.

### Snapshot

A libvirt snapshot named `clean` has been created on `fileguard-win-sandbox` (state `running` at creation time, confirmed via `virsh snapshot-list fileguard-win-sandbox`). This snapshot represents the known-good Windows analysis baseline with the CAPE agent already installed and reachable. Future deployment should produce and manage a reusable known-good sandbox image or automated snapshot process rather than manually reinstalling Windows, Python, and the CAPE agent for every environment.

### CAPE KVM Configuration

Relevant `/opt/CAPEv2/conf/kvm.conf`:

```ini
[kvm]
machines = fileguard-win-sandbox
interface = virbr10
dsn = qemu:///system

[fileguard-win-sandbox]
label = fileguard-win-sandbox
platform = windows
ip = 192.168.56.101
arch = x64
tags = win11
snapshot = clean
interface = virbr10
```

Important nuance: the guest is actually Windows Server 2025. `tags = win11` is a CAPE machinery compatibility/package-selection tag — CAPE's Windows machinery configuration expects a recognized OS-version tag (`winxp`, `win7`, `win10`, `win11`), and `win11` was chosen as the closest available tag for the PoC. This is **not** a claim that the guest is actually Windows 11, and may need revisiting if Server 2025 proves incompatible with behavior CAPE expects from that tag.

With this configuration, CAPE reports:

```
Using MachineryManager[kvm]
Loaded 1 machine
Waiting for analysis tasks
```

confirming CAPE recognizes the configured KVM sandbox.

### ResultServer

CAPE's ResultServer initially failed to bind because it was configured for `192.168.1.1:2042` — an address that does not exist on this host — causing `cape.service` to exit. It was corrected to the CAPE host's actual sandbox-facing address:

```ini
[resultserver]
ip = 192.168.56.1
port = 2042
```

After this correction, `cape.service` started successfully. The durable requirement is that the ResultServer address must be a CAPE host address the sandbox VM can actually reach — this must be templated or derived from the target environment during future deployment automation rather than left as an upstream default.

### Service State

Verified operational: `mongodb`, `cape`, `cape-rooter`, `cape-processor`, `cape-web`. CAPE successfully connects to MongoDB. `cape.service` reports the machinery-loaded/waiting-for-tasks state shown above. `cape-web` is reachable locally at `http://172.29.176.243:8000`, and the CAPE web UI has been verified to load.

Current non-blocking warnings observed (not resolved, just non-blocking for this PoC): inability to retrieve the pinned running Git commit hash, an optional missing `httpreplay` dependency, and Django deprecation warnings.

## Current Validation Status

**Verified:**
- CAPE host (Ubuntu + KVM/libvirt) is operational
- Isolated sandbox network exists and host-to-guest connectivity works
- Windows sandbox is built, with the CAPE agent installed, elevated, and reachable
- A clean snapshot exists with the agent available
- CAPE machinery recognizes and loads the configured sandbox
- CAPE's scheduler reaches "Waiting for analysis tasks"
- Core CAPE services (MongoDB, cape, cape-rooter, cape-processor, cape-web) are running
- The CAPE web UI is reachable

**Pending (not yet verified):**
- Submission of the harmless FileGuard behavioral sample through CAPE
- Successful CAPE orchestration of the Windows sandbox during an actual analysis
- Successful automatic snapshot revert cycle
- Successful behavioral report generation
- FileGuard retrieval of a CAPE JSON report
- A FileGuard `cape_client.py`
- CAPE report normalization
- `SUSPICIOUS` → CAPE application integration
- Dynamic IoC extraction
- AWS CAPE deployment
- Terraform for CAPE
- Production sandbox OS selection

**Current milestone:** CAPE infrastructure and sandbox registration are operational locally; first end-to-end harmless behavioral analysis remains pending.

## Important Implementation Lessons

**Kernel/MongoDB compatibility.** The Ubuntu VM initially booted kernel `7.0.0-30-generic`. The installed MongoDB version refused to start, reporting a known incompatibility with Linux kernel versions 6.19 and newer. The host already had the Ubuntu 24.04 GA kernel (`6.8.0-138-generic`) available; the host was configured to boot it instead, and MongoDB started successfully afterward, accepting local connections on `127.0.0.1:27017`. The durable lesson is not that kernel 6.8 must remain the permanent target — it is that the CAPE host requires a **tested and pinned** host/kernel/MongoDB combination. `6.8.0-138` is the currently validated local baseline; future infrastructure (including any AWS deployment) must explicitly pin and test its own compatible version set rather than assuming a newer default kernel will work.

**Disk/LVM sizing.** The Hyper-V VM was provisioned with a 100 GB virtual disk, but Ubuntu's root logical volume initially consumed only about 48.47 GB of it, leaving the host at roughly 92% filesystem utilization (~4 GB free) even though the underlying volume group still had ~48.47 GB free. CAPE reported insufficient free disk space as a result. The root LV was expanded to use the remaining VG capacity, producing a verified ~96 GB total / ~42 GB used / ~50 GB available (~46% used) filesystem. The lesson: provisioning a sufficiently large virtual disk is not enough — deployment automation must verify that the partition/LVM/filesystem layer actually consumes the intended capacity, not just that the underlying disk is large. The 100 GB figure is current PoC sizing, not a finalized AWS requirement.

**ResultServer interface selection.** Covered above — the ResultServer must bind an address the sandbox can reach, not an upstream example default.

**Isolated network requirement.** The sandbox network has no external forwarding and the guest has no default gateway, by design. This is a security requirement, not an oversight, and must be preserved identically in any future deployment.

**Guest agent readiness.** The CAPE agent must be elevated, reachable only from the CAPE host's sandbox-facing address, and already running via autostart at the moment the clean snapshot is captured — otherwise every snapshot revert would require manual reconfiguration before the sandbox is usable.

**Snapshot/image repeatability.** Manually installing Windows, Python, and the CAPE agent was acceptable to reach this PoC milestone, but is not repeatable. Future deployment should produce and manage a reusable known-good sandbox image or an automated snapshot-creation process.

**Configuration must be generated and tested, not defaulted.** Both the kernel/MongoDB issue and the ResultServer issue were caused by unexamined defaults — a newer-than-tested kernel and an upstream example IP address, respectively. Future deployment automation should generate and validate CAPE's configuration for the actual target environment rather than relying on defaults surviving unmodified.

## AWS Portability

What stays stable between the local lab and an eventual AWS deployment:
- The CAPE host shape: a Linux host running KVM/libvirt, hosting a disposable Windows guest
- Sandbox networking isolated from any trusted network by default, with no external forwarding
- FileGuard communicating with CAPE exclusively through its HTTP API — never libvirt, snapshot mechanics, or guest internals directly
- Disposition precedence and CAPE-eligibility policy living in FileGuard/OPA, not inside CAPE

What changes:
- The hypervisor hosting the CAPE Linux VM — Hyper-V locally, a nested-virtualization-capable EC2 instance on AWS (bare-metal instance families remain an option to evaluate later for performance/compatibility, not a default requirement)
- The network transport FileGuard uses to reach CAPE's API — a local Hyper-V network locally, private VPC networking on AWS
- How the CAPE host and Windows sandbox are built — manual local steps here, deployment automation later

The isolation layering is conceptually identical in both environments:

```
AWS VPC/subnet/security groups
  → EC2 CAPE host ENI
  → CAPE host Linux firewall/routing
  → isolated libvirt/KVM guest network
  → Windows sandbox guest
```

The Windows sandbox is never a first-class EC2 instance and receives no AWS security group of its own. Its isolation is enforced by the CAPE host's own network configuration (the libvirt virtual network plus host firewall rules) — the same mechanism already in use locally, not an AWS-native control.

## Future Deployment Automation Requirements

Not implemented yet. A future automated deployment should account for:

- [ ] Selecting a supported nested-virtualization-capable EC2 instance family (bare-metal evaluated separately if needed)
- [ ] Sizing and validating encrypted EBS storage, including verifying the LVM/filesystem actually consumes the provisioned capacity
- [ ] Pinning and testing a compatible Ubuntu/kernel/MongoDB baseline before deployment
- [ ] Automating KVM/libvirt installation
- [ ] Automating CAPE installation
- [ ] Automating MongoDB installation and compatibility validation
- [ ] Automating isolated libvirt network creation (no external forwarding)
- [ ] Templating/deriving CAPE ResultServer configuration for the target host
- [ ] Generating CAPE's `kvm.conf` for the target environment rather than hand-editing it
- [ ] Building/provisioning a prepared Windows sandbox image
- [ ] Automating CAPE agent installation and configuration in that image
- [ ] Automating clean snapshot/image lifecycle management
- [ ] Automating service enable/start for all CAPE components
- [ ] Running preflight/health validation before considering a host ready

This work should be conceptually separated rather than collapsed into a single Terraform module:

- **Terraform** — AWS infrastructure only (networking, EC2, EBS, security groups)
- **CAPE host bootstrap/image configuration** — Linux/KVM/CAPE dependencies and configuration
- **Windows sandbox image** — the prepared, disposable analysis guest
- **FileGuard application** — communicates with CAPE only through the stable API/client boundary described below

Terraform alone should not be expected to contain all of this operating-system-level configuration.

## CAPE Readiness / Health Criteria

This is a future automation concept, not something currently implemented in FileGuard. A CAPE host should not be considered ready merely because `cape.service` is running. Future automated preflight/readiness checks should validate at least:

- The kernel is on the expected/tested baseline
- Sufficient filesystem free space is available
- MongoDB is running and reachable
- KVM is available
- libvirt is operational
- The expected isolated network exists
- The expected sandbox VM is registered
- The expected clean snapshot/image exists
- The CAPE agent is reachable from the host
- The CAPE ResultServer can bind and listen
- CAPE machinery successfully loads the configured machine
- The CAPE scheduler reaches "Waiting for analysis tasks"

## Known PoC Limitations

- Windows Server 2025 is the current PoC guest, used for plumbing/integration validation — it is not yet a finalized production sandbox OS decision. CAPE upstream generally recommends supported desktop Windows versions (10/11), and the guest may be replaced if compatibility problems appear.
- The `win11` CAPE machinery tag is a compatibility/package-selection tag required by CAPE's configuration format — it is not a claim that the guest is actually Windows 11.
- First end-to-end harmless behavioral analysis (submission → sandbox orchestration → snapshot revert → report generation → retrieval) has not yet been completed.
- No real malware has been used, or is planned for use, in this lab.
- No FileGuard CAPE API client exists yet.
- No AWS CAPE deployment or Terraform for CAPE exists yet.
- CAPE dynamic analysis does not determine or guarantee whether a file is malicious or benign — like static analysis, it produces evidence for analyst review. A `CLEAN` static disposition is likewise never a guarantee of safety.
