---
layout: post
title: "HackTheBox CAPE Certification"
date: 2025-03-15
tags: [certification, htb, active-directory]
description: "My experience with the HackTheBox CAPE exam — preparation, the exam itself, and tips for anyone considering it."
---

## TL;DR

- CAPE (Certified Active Directory Penetration Testing Expert) is HackTheBox's most advanced AD-focused certification, requiring ~3–4 months of dedicated preparation and a 10-day practical exam
- The certification combines comprehensive learning (15 modules) with a challenging practical exam that tests both technical skills and report writing abilities
- Key success factors: strong AD fundamentals (CPTS recommended), dedicated study time, thorough documentation, and report writing skills
- Worth it if you're serious about AD security, but not an entry-level cert — expect to invest 160–320 hours total (learning path + exam)
- Best suited for security professionals looking to master enterprise AD security, whether from red or blue team backgrounds

---

## Introduction

I recently achieved something remarkable — passing the HackTheBox CAPE exam on my first attempt. As one of the few individuals who've accomplished this feat, and noticing the lack of comprehensive reviews, I decided to share my experience with the cybersecurity community.

## About CAPE

![CAPE Certification Logo](/assets/images/cape-certification/cape-logo.png)

HackTheBox CAPE (Certified Active Directory Penetration Testing Expert) stands as one of the most rigorous certifications in the cybersecurity landscape. As HTB's fifth certification offering, it distinguishes itself through its laser focus on Active Directory penetration testing.

Before attempting the certification exam, candidates must complete an intensive learning path consisting of 15 comprehensive modules — 6 medium-difficulty and 9 hard-difficulty. The curriculum is meticulously designed to cover every aspect of Active Directory security:

- **Active Directory Enumeration** — mastering both external tools (PowerView, BloodHound) and built-in Windows utilities
- **Windows Lateral Movement** — deep dive into protocols like WMI, SMB, RDP, DCOM, and WSUS exploitation
- **Netexec** — the Swiss Army knife of AD pentesting, offering versatile attack capabilities
- **Kerberos Attacks** — comprehensive coverage of Kerberos authentication vulnerabilities
- **DACL Attacks** — exploring common privilege escalation paths and advanced techniques like GPO abuse
- **NTLM Relay Attacks** — achieving privilege escalation without credential compromise
- **ADCS Attacks** — in-depth exploration of 11 ESC paths using modern tools like Certipy and Certify
- **Active Directory Trust Attacks** — both intra-forest and cross-forest exploitation techniques
- **C2 Operations** — hands-on experience with the Sliver C2 framework
- **Windows Evasion Techniques** — advanced methods to bypass Windows Defender (having your own Visual Studio installed is my recommendation)
- **Enterprise Service Attacks** — essential techniques for compromising MSSQL, Exchange, and SCCM

> The learning path assumes foundational knowledge in penetration testing methodology and general security concepts. Prior completion of CPTS is highly recommended.

## About the Exam

The CAPE exam simulates a real-world internal penetration test against an enterprise Active Directory environment. Candidates are tasked with conducting a professional security assessment that includes reading and acknowledging a letter of engagement, identifying and exploiting vulnerabilities and misconfigurations, and producing a comprehensive, commercial-grade penetration testing report.

### Key Exam Details

- **Duration:** 10 days to complete both the penetration test and submit the final report
- **Environment:** Dedicated testing environment accessible via VPN
- **Format:** Non-proctored examination
- **Objectives:** Multiple flags must be captured to demonstrate progress
- **Retake Policy:** Free second attempt within 14 days if initial report is submitted, with detailed examiner feedback on your first attempt
- **Assessment:** Primary evaluation based on report quality, not just flag capture

### Time Management

The 10-day exam duration is both a blessing and a challenge. Unlike typical 24/48-hour certification exams, CAPE requires careful time management and dedication:

- It's not recommended to attempt this exam "after-hours" or alongside regular work
- The complexity demands focused, dedicated time for both testing and documentation
- Report writing alone can take multiple days to complete properly

### Technical Aspects

- The exam environment is fully dedicated to each candidate
- Environment can be reset as needed, but changes are not persistent
- Machine resets affect the entire environment, not individual systems
- Multiple complex steps are typically required to capture each flag

### Report Requirements

The report is the cornerstone of the exam evaluation:

- A mandatory template must be followed
- Each finding requires detailed documentation and evidence
- Recommendations must demonstrate meaningful impact on environmental security
- Quality and completeness of the report directly determine exam success

> While flag capture demonstrates technical ability, the report's quality is the primary factor in passing the exam. The second attempt opportunity is only provided if a complete report was submitted in the first attempt.

---

## Preparations

### My Background

![A true cybersecurity master wields both the blue and red side](/assets/images/cape-certification/blue-red-side.png)

As a detection engineer and threat hunter by profession, my journey to CAPE was somewhat unconventional. Despite never having conducted a formal penetration test in a real environment, I firmly believe in the principle: *"to catch a hacker, you need to think like one"* (if you've read Mitnick's *Ghost in the Wires* — you know what I mean). This mindset, combined with my blue team experience, led me to pursue offensive security certifications.

### Prerequisites and Prior Experience

My path to CAPE included several key milestones:

- **CPTS Certification** — completed HackTheBox's Certified Penetration Tester Specialist exam, which I consider essential groundwork for CAPE
- **Pro Labs Experience** — completed multiple HTB Pro Labs including Dante, Zephyr, Offshore, and Alchemy, strengthening my methodology in enterprise-like environments
- **CRTP Certification** — finished Altered Security's Red Team Professional course, providing additional AD-focused expertise from a red team perspective

### The Learning Path Experience

The CAPE learning path requires a Gold Subscription to HackTheBox. What sets HTB's learning approach apart is their focus on practical, hands-on learning through reading, understanding, and performing. Instead of relying on potentially outdated video tutorials, the content remains current and accessible even after subscription expiration. I did it slowly but steadily, trying to dedicate at least a few hours every week.

### Standout Modules

Three modules particularly impressed me during the learning path:

**1. ADCS Attacks**
Comprehensive coverage of AD CS misconfigurations, aligned with SpecterOps' cutting-edge research, with a clear explanation of complex exploitation paths.

**2. Introduction to Windows Evasion Techniques**
A unique approach to defensive bypass techniques covering static/dynamic analysis, process injection, AMSI and UAC bypass, AppLocker evasion, and PowerShell Constrained Language Mode. Hands-on coding with Visual Studio is recommended.

**3. Using NetExec (formerly CrackMapExec)**
A deep dive into this versatile tool's capabilities, with practical applications for streamlining AD penetration testing.

All modules remain accessible post-completion, serving as valuable reference material during the exam and future engagements.

---

## The Exam Experience

### Setup and Environment

Picture this: 10 days of pure focus, a complex enterprise AD environment, and a mission to compromise it completely. That's the CAPE exam in a nutshell. Drawing from my previous HTB CPTS experience, I approached this challenge with a carefully prepared environment:

- **Kali Linux VM** — pre-configured with tools from the learning path
- **Windows 10 VM** — equipped with Visual Studio for evasion techniques
- **Obsidian** — for comprehensive note-taking, crucial for report writing

### The Journey

The exam proved to be a true test of understanding rather than mere tool proficiency. Several key observations stood out:

- **Deep Understanding Required** — simply following "exploit playbooks" proved insufficient; each challenge demanded thorough comprehension of the underlying concepts
- **Continuous Learning** — even during the exam, I found myself researching newly discovered vulnerabilities to fully understand their impact
- **Persistence Pays Off** — what initially seemed like impenetrable barriers became stepping stones with a methodical approach
- **Building Momentum** — each successful exploitation provided momentum for tackling subsequent challenges

I was about to give up on day 6. I didn't.

![Persistence pays off](/assets/images/cape-certification/day6-meme.png)

### Mental Approach

The exam tested not just technical skills but also mental resilience:

- **Taking Breaks** — regular walks helped clear my mind when faced with challenging obstacles
- **Self-Care** — maintaining good sleep patterns and regular meals proved crucial for sustained performance
- **Attention to Detail** — often, a small overlooked detail was the key to progress
- **Time Management** — completing 90% of the technical portion 36 hours before deadline allowed adequate time for report writing

### Final Push

![Day 1 vs Day 10](/assets/images/cape-certification/day1-vs-day10.png)

The last phase of my exam journey included dedicating a full day to report writing, resulting in a comprehensive **142-page document**, and using the final 6 hours to achieve 100% completion of all objectives.

---

## Conclusions and Advice

### Overall Assessment

CAPE stands out as an exceptional learning path and certification for anyone serious about Active Directory security. It provides in-depth knowledge of AD security concepts, offers practical real-world scenarios, and prepares you thoroughly for enterprise-level challenges.

### Time Investment

This is not a certification to be taken lightly:

- Learning path: ~36 days (~100–200 hours)
- Exam preparation and execution: 60–120 hours
- **Total commitment: expect to invest 3–4 months of dedicated study**

### Prerequisites

CAPE is definitely an intermediate-level certification. Before attempting it, ensure you:

- Have completed CPTS certification
- Have experience with several HTB Pro Labs
- Are comfortable with pivoting and lateral movement
- Know multiple tools for each attack technique
- Have strong environment awareness skills

### Key Tips for Success

**Documentation**
- Take detailed notes during the exam
- Document every exploitation path
- Keep organized records of all credentials
- Start report writing early

**Learning Path Approach**
- Don't rush through the modules
- Understand the *why* behind each technique
- Use modules as reference material during the exam
- Review challenging modules before the exam

**Exam Strategy**
- Prepare your VM environment in advance
- Practice thorough enumeration — it is key
- Take regular breaks when stuck
- Maintain work-life balance during the exam

### Final Thoughts

CAPE is more than just another certification — it's a transformative journey into the depths of Active Directory security. While it may not yet have widespread HR recognition, its technical depth and practical approach make it invaluable for security professionals. The certification's commitment to keeping materials current and relevant ensures that the skills you gain will remain applicable in real-world scenarios.

The journey through CAPE isn't just about passing an exam — it's about becoming a more competent cybersecurity professional.

---

*This post was originally published on [Medium](https://medium.com/@filip.bartosz.wozniak/hackthebox-cape-certification-700737050cd6).*
