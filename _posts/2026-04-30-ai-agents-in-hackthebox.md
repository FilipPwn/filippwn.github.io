---
layout: post
title: "Building an OpenCode Agent Team for HackTheBox: A Field Report"
date: 2026-04-30
tags: [ai, agents, opencode, hackthebox, offensive-security, ctf]
description: "Retrospective of running a multi-agent OpenCode setup across eight HackTheBox machines — what worked, where the agents struggled, and the operating rules that came out of it."
---

## Introduction

I spent a set of HackTheBox runs using an [OpenCode](https://opencode.ai) based agent setup designed less like a chatbot and more like a small offensive security team. The goal was simple: give the AI enough structure to behave like a disciplined operator, not a command generator.

This post is a retrospective of that setup — what worked, where the agents struggled, and what I changed.

This is not a benchmark. The sample is small, the boxes are heterogeneous, and several runs included human hints or corrections. But the logs are real enough to show what matters when using AI agents for CTF-style offensive security.

## The Setup

The workspace is organized around a global operating manual and specialist OpenCode agents. The main rulebook is `~/htb_machines/AGENTS.md` — it defines the mission, scope controls, artifact discipline, credential handling, hash handling, pivoting rules, and the completion checklist.

Each agent is a single Markdown file under `~/.config/opencode/agent/`, with one orchestrator (`htb-lead`) dispatching four phase specialists.

![OpenCode agent team layout](/assets/images/ai-agents-htb/img_agents.png)

The setup also uses supporting skills under `~/htb_machines/.skills/`:

- `artifact-management` — workspace structure and evidence handling
- `python-tooling` — safe Python execution rules on Kali
- `tool-installation` — custom tool installation under `/opt/<toolname>/`

The latest version also wires in Kali's packaged MCP bridge (`mcp-kali-server`). That MCP layer mattered in practice.

## The Dataset

I reviewed these substantive machine workspaces:

| Machine | Outcome | Notes |
|---------|---------|-------|
| `onetwoseven` | Pwned | Linux/web chain, SFTP, symlink/source disclosure, apt privesc |
| `spooktrol` | Pwned | C2/API abuse, file read/upload traversal, container to host root |
| `pingpong` | Pwned | Kerberos-only AD, ESC13, trust pivot, gMSA, RBCD, AD CS |
| `garfield` | Pwned | AD ACLs, scriptPath, Ligolo pivot, RODC abuse, KeyList/PRP |
| `logging` | Pwned | AD creds from logs, shadow creds, scheduled task DLL hijack, rogue WSUS |
| `snapped` | Pwned | Nginx UI RCE, hash cracking, snapd CVE privesc |
| `devarea` | Pwned | SOAP XOP/MTOM file read, Hoverfly RCE, symlink-chain root file read |
| `silentium` | Pwned | Flowise reset/API abuse, Custom MCP RCE, container env secrets, Gogs symlink write |


Across the eight real runs, every machine reached a `PWNED` timeline entry. That headline sounds better than the story actually is — some boxes were solved cleanly by the agents, while others required hints, guidance or corrected assumptions.

## What Worked Well

### 1. Artifact discipline made the agents auditable

The strongest part of the setup was not exploitation — it was memory.

Every machine had a predictable structure. Every tool run wrote an artifact. Every meaningful action got a `timeline.md` entry through a small `htb_log` shell helper.

![Workspace layout of htb_machines/silentium](/assets/images/ai-agents-htb/img_workspace.png)

This made it possible to reconstruct decisions after the fact. For example, `onetwoseven/timeline.md` shows a complete progression from signup-generated credentials, to SFTP symlink probes, to admin source disclosure, to cracked credentials, to uploaded addon RCE, to sudo apt abuse.

The logs also show good handoff points:

```text
spooktrol/timeline.md: HANDOFF: -> @web-exploit | reason: Uvicorn API exposes downloadable implant with API strings and endpoints
spooktrol/timeline.md: HANDOFF: -> @privesc | reason: root shell in container spook2; need host escape/root
```

That kind of handoff is exactly what multi-agent workflows need. The receiving agent does not have to infer the entire state from chat history — it can read `notes/attack-plan.md` and the relevant artifacts.

The clearest single example is silentium's timeline. You can read the entire kill chain from recon to root flag on one screen:

![silentium timeline excerpt](/assets/images/ai-agents-htb/img_timeline.png)

### 2. Credential reflexes were consistently useful

The agents were good at treating credentials as events, not trivia.

Examples from the timelines:

- `logging`: recovered a service credential from `Logs/IdentitySync_Trace_20260219.log`, sprayed it, then later derived stronger candidates from rotation clues.
- `onetwoseven`: generated SFTP credentials through signup, then created a localhost-only account through SSH forwarding.
- `garfield`: after obtaining control over `l.wilson`, the agent reset `l.wilson_adm`, sprayed each candidate, and quickly found the working path.
- `silentium`: extracted a host SSH password from the Flowise parent process environment after first landing in a container.

This was one of the clearest wins from codifying behavior in `AGENTS.md`:

![Credential and hash reflex rules from AGENTS.md](/assets/images/ai-agents-htb/img_reflex.png)

The agents followed that pattern often enough that it materially improved progress. The byproduct is a clean, greppable per-machine ledger:

![silentium credential ledger](/assets/images/ai-agents-htb/img_credentials.png)

### 3. Recon was fast and usually well-scoped

The `recon` agent performed well on the basic loop:

- verify active target
- verify VPN
- run full TCP and top UDP
- run detail scan
- inspect web manually before fuzzing
- map vhosts
- dispatch based on service pattern

Good examples:

- `spooktrol`: found ports `22,80,2222`, extracted implant strings, and handed off to web exploitation.
- `snapped`: found `admin.snapped.htb`, identified Nginx UI `2.3.2`, extracted frontend JS endpoints, and handed off with a precise target.
- `logging`: identified a DC, discovered `logging.htb` / `DC01.logging.htb`, pulled readable SMB logs, and found a service credential before deeper AD work.

The important lesson: AI recon improves dramatically when the prompt forbids blind fuzzing before manual review. The `web-exploit` agent's first rule is *"Read the app before fuzzing it,"* and the timelines show that instruction paying off.

### 4. AD work benefited from tool hierarchy and explicit reflexes

The AD runs were the most impressive when they stayed inside the checklist.

On `pingpong`, the agent chain handled:

- Kerberos-only auth constraints
- AD CS ESC13 certificate request
- PKINIT time skew
- WinRM foothold
- pivot to an internal `pong.htb` network
- gMSA abuse
- RBCD
- AD CS escalation back to Administrator

On `garfield`, the chain was more complex:

- initial AD ACL exploration
- scriptPath abuse
- Ligolo pivot through DC01
- RODC01 enumeration
- RBCD to SYSTEM on RODC01
- krbtgt RODC material extraction
- PRP modification
- final Administrator material and root flag

These are long chains with many opportunities to lose state. The agent setup held together because every phase wrote artifacts and updated `attack-plan.md`.

### 5. The agents were good at turning footholds into context

The best example is `silentium`.

After Flowise exploitation landed in a container, the agent did not stop at `id`. It exfiltrated environment data and specifically compared the child shell context against `/proc/1/environ`:

```text
silentium/timeline.md: exfiltrated container environment via Custom MCP RCE
silentium/timeline.md: exfiltrated /proc/1/environ for Flowise parent process
silentium/timeline.md: CRED: ben:<redacted> from Flowise /proc/1/environ; SMTP_PASSWORD also found
```

That behavior came directly from an operating rule added after earlier observations:

> When command execution lands inside a containerized web app, compare the child process environment with the parent application process environment such as `/proc/1/environ` when readable.

This is the kind of rule that makes agents better over time. It captures an operational lesson in a way that future runs can reuse.

## Where the Agents Struggled

### 1. "Ruled out" was sometimes too strong

The clearest failure was `devarea`.

The agent initially tested SOAP XXE and related XML vectors and concluded that XXE was not exploitable:

```text
devarea/timeline.md: SOAP XXE variants complete | RESULT: DTD event rejected before entity resolution; no OOB callbacks; no files read; no creds
```

Later, the I've clarified that the intended issue was not classic DTD XXE, but SOAP XOP/MTOM file read with a base64 response:

```text
devarea/timeline.md: user clarified XXE via SOAP is XOP/MTOM file-read with base64 response
devarea/timeline.md: XOP/MTOM file read confirmed | RESULT: /etc/passwd, /proc/self/environ, and Hoverfly service credentials recovered
```

That is a high-value lesson: **vulnerability classes are not single tests**. "XXE" can mean DTD entities, XInclude, schema imports, XOP/MTOM attachment dereferencing, content-type parser confusion, or framework-specific XML binding bugs.

After this, I added a stronger rule to `AGENTS.md`: before ruling out a vulnerability class, decompose it into subtypes and record which were tested.

### 2. The agents needed human hints on some intended paths

The timelines are honest about this.

- `snapped`: a hint corrected the privesc focus to a snapd CVE.
- `garfield`: hints clarified the relative SYSVOL scriptPath chain and later reiterated the RODC Ligolo / RBCD / KeyList path.
- `pingpong`: a hint supplied a JEA/history credential after local access to the intended source was blocked.
- `devarea`: user clarification corrected the SOAP file-read primitive.

This does not make the setup useless. It means the agents were effective operators but not always effective puzzle-solvers. They could execute complex chains once pointed at the right primitive, but they sometimes missed the intended semantic leap.

### 3. Long AD chains still need better strategic search

`garfield` is both a success and a warning.

The agent was persistent and well-documented, but the timeline shows many blocked branches: MAQ/noPac attempts, scriptPath monitoring, LDAP relay/RBCD, Hyper-V reassessment, RDP reassessment, RODC KeyList failures, PRP changes and retries.

The final solution worked, but the path was noisy. The agent was good at executing hypotheses; it was less good at ranking them early.

For complex AD boxes, the next improvement is not more tools. It is better graph reasoning: extracting BloodHound paths, encoding likely HTB-intended chains, and explicitly comparing the shortest viable paths before launching more attempts.

## Machine Notes

### OneTwoSeven

One of the cleanest runs. The agents chained: signup-generated SFTP credentials, SSH local forwarding to create a localhost-only user, SFTP chroot/symlink source disclosure, cracked admin hash, admin addon upload/rewrite bypass to shell, sudo apt proxy/package privesc.

Lesson: the agents performed well when the exploit path was a sequence of local observations. Each new artifact naturally led to the next test.

### SpookTrol

A strong web/API run. The agent reversed the implant behavior, abused arbitrary file read, registered as a fake implant, confirmed upload traversal, overwrote the FastAPI app, then used the C2 database tasking model to escape from container root to host root.

Lesson: C2-themed boxes reward application-specific reasoning. The agent did well because it inspected the implant and live task database instead of looking for generic container escapes.

### PingPong

A strong AD execution run with a human-assisted middle. The agents handled ESC13, Kerberos time skew, certificate auth, pivoting, gMSA material, RBCD, and final AD CS escalation. .

Lesson: the AD agent is good at operating a known chain, but still needs improvement in finding hidden intended clues behind constrained endpoints.

### Garfield

The most complex run. The agents eventually solved it through relative SYSVOL scriptPath, l.wilson to l.wilson_adm, Ligolo pivoting, RODC abuse, RBCD, PRP modification, and Administrator material recovery. It also required hints and produced the noisiest timeline.

Lesson: persistence and artifact discipline prevented collapse, but strategic ranking needs work.

### Logging

A good example of composable AD/web/privesc behavior. The agents recovered credentials from logs, derived better candidates, used shadow credentials against `msa_health$`, obtained WinRM command execution, abused an UpdateMonitor DLL execution path for user, then used AD CS plus rogue WSUS to reach root.

Lesson: credential reflex plus service-specific follow-up is a strong pattern.

### Snapped

The web half was solid: Nginx UI version identification, restore RCE, database dump, bcrypt cracking, and user flag. The root path needed a hint around snapd CVE focus.

Lesson: agents can handle public-version web exploitation well, but CVE triage should be more precise and should avoid chasing similarly numbered but unrelated vulnerabilities.

### DevArea

The best example of a near miss becoming a prompt improvement. The agents initially ruled out SOAP XXE too narrowly. Once XOP/MTOM file read was clarified, they recovered Hoverfly credentials, got RCE, and then reached root through a SysWatch symlink-chain root file read.

Lesson: teach agents vulnerability taxonomies, not just payload lists.

### Silentium

This run showed the value of newer operating rules. The agent used Kali MCP for nmap when sudo was unavailable, exploited Flowise reset/API behavior, used Custom MCP RCE, extracted parent process environment secrets from `/proc/1/environ`, SSHed as the real user, then abused local Gogs symlink write behavior to root.

Lesson: the setup is improving. Later rules directly helped later boxes.

## What I Changed After Reviewing the Runs

### Added Kali MCP as a first-class tool path

The official Kali `mcp-kali-server` is now connected to OpenCode. Agents have permission for `mcp-kali-server_*` tools. This gives the agents a fallback when shell context is awkward, especially for standard Kali tools like nmap.

### Made `/opt` the custom tool contract

Agents now explicitly know:

- custom tools go in `/opt/<toolname>/`
- check `/opt/<toolname>/` and `PATH` before use
- if missing, read `tool-installation/SKILL.md`
- install only into `/opt/<toolname>/`
- add wrappers / symlinks under `/usr/local/bin/`
- update `/opt/TOOLS.md`

This matters because CTF agents frequently waste time rediscovering missing tooling. **Tool availability should be boring.**

### Strengthened vulnerability-class decomposition

The `devarea` miss led to a stronger rule:

> Before ruling out a vulnerability class, decompose it into relevant subtypes and record which were tested.

That rule exists because *"tested XXE"* was not enough. The agent tested classic DTD-style XXE, but the bug lived in XOP/MTOM behavior.

### Added container parent environment checks

The `silentium` win reinforced a rule that should be standard:

> When command execution lands inside a containerized web app, compare the child process environment with `/proc/1/environ` when readable.

Spawned shells often have stripped environments. The parent process often has the real deployment secrets.

## Overall Assessment

The agents were effective, but not magical.

They were strongest at:

- repeatable recon
- preserving state across long attacks
- disciplined credential and hash handling
- following AD and web exploitation playbooks
- turning footholds into deeper context
- documenting what happened

They struggled with:

- subtle intended-path inference
- overconfident negative conclusions
- CVE ambiguity
- long AD graph strategy
- missing local tooling

The biggest engineering lesson is that **AI agents need operational rails more than they need clever prompts**. The useful parts of this setup are mundane:

- one workspace layout
- one timeline format
- explicit handoffs
- strict scope checks
- standardized credential reflexes
- standardized tool installation
- a habit of writing down failed hypotheses

That structure turned OpenCode from a chat interface into something closer to a junior operator with a runbook and a team lead.

## Practical Recommendations

If you are building your own HTB agent setup, I would start here:

1. Create a strict workspace structure before touching the target.
2. Require every tool run to write an artifact.
3. Put shared state in `notes/attack-plan.md`, not in chat history.
4. Split agents by phase: recon, web, AD, privesc.
5. Encode reflexes: credentials, hashes, vhosts, pivots, container envs.
6. Force agents to write `notes/stuck.md` with alternative hypotheses when they loop.
7. Treat custom tools as infrastructure and install them under `/opt` only.
8. Add MCP or another stable tool bridge for standard Kali tooling.
9. Do not let agents say *"ruled out"* unless they list the subtypes tested.
10. Expect to give hints on puzzle boxes; measure whether the agent can exploit and document the corrected path.

## Final Take

The setup is good enough to be useful on real HTB-style workflows, especially when the target rewards methodical enumeration and stateful exploitation. It is not flawless, and it should not be trusted blindly. The best results came from treating the AI as an operator inside a controlled engineering system: scoped, logged, artifact-driven, and forced to explain what it tried.

That is the real lesson from these machines. The "AI" part helped with speed and breadth, but the "engineering" part made the work reliable.
