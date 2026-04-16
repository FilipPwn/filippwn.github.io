---
layout: post
title: "Cybersecurity Certifications: My Journey and Thoughts"
date: 2026-04-15
tags: [certification]
description: "My journey and thoughts about cybersecurity certifications."
---

## Introduction

I've been working in the cybersecurity field for a few years now and during that time I've worked on a few certifications. Here's the list of them, and later some thoughts about them.

## Certifications
Important notes:
- Some of these may be expired - I obtained them, I just didn't always renew them 😄
- I've bought some of them, some of them were sponsored by my company

**2022**
- CompTIA: Security+
- Elastic: Certified Engineer
- Elastic: Certified Observability Engineer
- Elastic: Certified Analyst
- CompTIA: CySA+ (Cybersecurity Analyst)

**2023**
- GIAC: GCDA + SANS SEC555
- GIAC: GDAT + SANS SEC599

**2024**
- HackTheBox: CPTS (Certified Penetration Tester Specialist)
- Altered Security: CRTP (Red Team Professional)

**2025**
- HackTheBox: CAPE (Certified Active Directory Penetration Testing Expert)
- Altered Security: CRTE (Red Team Expert)
- HackTheBox: CWES (Certified Web Exploitation Specialist)
- OffSec: OSCP (Offensive Security Certified Professional)

## Thoughts

### CompTIA Security+
CompTIA Security+ was my first certification. I was fresh out of university and I wanted to validate my knowledge about general cybersecurity concepts. Security+ is a **well-known and well-regarded** certification in the industry. It covers a wide range of topics (*very broad, but not necessarily deep*). It can be considered a good starting point for someone who wants to start their journey in the cybersecurity field.

I prepared for this certification using mainly a **Udemy course** (videos + mock exams). Udemy is a good platform for self-paced learning and it is very affordable. I spent around **2-3 weeks** watching videos and writing notes. After that I took the exam - it is **proctored** and **theory only** (multiple choice questions). What stood out for me is that the exam uses very advanced English words and phrases, so it is also a good opportunity to practice your English.

**Pros:**
- Good starting point for someone who wants to start their journey in the cybersecurity field
- Widely known and respected certification in the industry

**Cons:**
- Very broad, but not necessarily deep
- Not very practical
- Valid for 3 years

### CompTIA CySA+
CySA+ wasn't a certification that was on my radar, but I got a pretty good discount for it - I think it was around **80%**, and it was a "beta" exam. I used the same strategy as for Security+ - Udemy course + mock exams. At that time I was already working in the cybersecurity field, so I had working knowledge about most of the topics covered in the exam - SIEM, IDS, IPS, investigations, incident response, threat intelligence, etc.
The exam was probably easier than Security+ - a bit deeper in security analysis, but still *very theoretical*.

**Pros:**
- Good at a discount rate
- Quite easy exam

**Cons:**
- Not as well known as Security+
- Not very practical
- Valid for 3 years

### Elastic Certifications
I've done three Elastic certifications available at that time:
- Elastic Certified Engineer
- Elastic Certified Observability Engineer
- Elastic Certified Analyst

Elastic teaches **practical skills** and knowledge about **Elastic Stack** and its products. If you ever work with Elastic Stack as an engineer or architect, these training and certifications could be very beneficial for you.

**Engineer** course teaches you mostly about Elasticsearch - how it works, how to use the API, working with indices, mapping, ingestion, search, aggregation, etc. The only thing missing, in my opinion, is how to deploy and scale your own Elasticsearch cluster.

**Observability** course teaches you how Elastic can be used to monitor and analyze your logs, metrics, and traces for your applications - like nginx, apache etc. It also shows how things like APM or Heartbeat work.

**Analyst** course was the easiest one - it teaches you how to use Kibana - visualizations, dashboards, maps etc.

All of the exams are **proctored and practical** - you have very limited time to complete around 10 tasks. You have to be really confident about what you are doing. Tip: **know how to use Elastic docs**.

I think that right now there is also another course: Elastic Certified Security Engineer, but I haven't done it.

**Pros:**
- Practical skills around Elastic Stack
- Beginner friendly

**Cons:**
- Probably only for Enterprise customers, I wouldn't buy it by myself
- Good for beginners, but it is missing some advanced topics
- Valid for 3 years

### GIAC: GCDA
SANS SEC555 and GCDA were my first SANS and GIAC courses. GCDA stands for **GIAC Certified Detection Analyst** - and that's why I've done it, to become a detection engineer. At that time it was taught by **Justin Henderson** and I must say: I love this guy and his teaching style. I love his jokes and his way of explaining things. The course teaches how to start with detection engineering: how to choose and build a SIEM, make it "tactical", how to feed it (and not overfeed it), how to use it, build detections / enrichments, etc. *This is probably the only course that will teach you that* - how to architect a SIEM solution in your enterprise. Great stuff, but for a great price too. Exam is proctored, but as with most typical GIAC exams - it is **open-book**.

Right now SEC555 is taught by another instructor, so I cannot say much about it.

**Pros:**
- Must have for SIEM Architect / Detection Engineer
- Tons of practical knowledge about SIEM
- Probably the only course that will teach you how to architect a SIEM solution in your enterprise
- Based on Elastic Stack - very applicable in real-world

**Cons:**
- Expensive
- Valid for 3 years

### GIAC: GDAT
SANS SEC599 was the second SANS course that I've done - with GDAT (**GIAC Defending Advanced Threats**) certification. It is designed to be a **purple-team** certification - you will learn how to emulate some threats and then how to defend against them. The course is very practical and is taught by experienced instructors. It was not as game-changing as GCDA, but it was a good supplement to my knowledge. To be honest, *most of the "red" stuff was really basic*, so do not expect to learn advanced red-team techniques. Exam was proctored, similar to other GIAC exams.

**Pros:**
- Purple-team certification (only one in the industry?)
- Practical skills about red-team and purple-team
- Elastic Stack is used as a SIEM

**Cons:**
- Expensive
- Red-team stuff is really basic
- Valid for 3 years

### HackTheBox: CPTS
Here we go, my first HackTheBox course and certification. **HackTheBox** is probably the most popular and practical platform to learn cybersecurity skills. Their academy started a few years ago and it is a blast! Before that course, I wasn't that self-confident about my pentesting skills. The course teaches you everything that a solid pentester should know: enumeration, exploitation, lateral movement, some web skills, some basic Active Directory attacks, some networking skills. All very applicable. To complete the course, you probably need a few weeks/months of dedicated study - but it is totally worth it. Very practical labs, up-to-date content and tools, great community (discord). The exam is **not proctored**, but it lasts **10 days** (I've personally used all that time). The report is mandatory, and it has to be a very professional one - probably need a whole day for it. Nevertheless, **passing CPTS was a game-changer for me**. It opened my eyes to the world of pentesting and I've started to love it.

**Pros:**
- Inexpensive (silver subscription, annual - is enough)
- Most practical course about pentesting I've ever seen
- Up-to-date content
- Starting to grow in recognition
- Exam is a real pentest, and it is a real challenge

**Cons:**
- Not as recognized as OSCP

### Altered Security: CRTP
Altered Security (led by **Nikhil Mittal**) specializes in Active Directory and Azure security. I wanted to go deeper in Active Directory security at that time, and HackTheBox CAPE was not available yet. What is good about CRTP is that it is a **beginner-friendly** course, quite inexpensive, and **materials are for life** (only lab time is limited). Material taught here is useful for both offensive and defensive operators. The course brings its own VM in cloud, available via Guacamole, which is very smooth. Exam is not proctored, but it is a realistic Active Directory pentest - ending with a report.

**Pros:**
- Inexpensive
- Materials are for life and updated
- Great teacher
- Beginner friendly

**Cons:**
- Not that much recognized

### HackTheBox: CAPE
Just after I've finished CRTP, HackTheBox released CAPE. It is a certificate for **"seniors"** in Active Directory security. The course is probably now **the best in the industry** - teaches advanced AD stuff like AD CS, basic Defense Evasion, advanced enumeration and so on. I've written a dedicated post for it here: [HackTheBox CAPE Certification](https://filippwn.github.io/blog/2025/03/hackthebox-cape-certification/). Exam is not proctored and lasts **10 days** - and it was the **most challenging and rewarding exam** that I've experienced so far. By the way - I was the **10th person** to pass it.

**Pros:**
- Best course about AD security in the industry
- Exam is a real pentest, and it is a real challenge
- Report has to be professional and detailed
- AD CS attacks are covered

**Cons:**
- Not yet recognized that much

### Altered Security: CRTE
For Black Friday I decided to buy CRTE - a more advanced course than CRTP. I went through it at a faster pace and it is a bit more advanced. I was a bit disappointed that there was *not that much new stuff* compared to CRTP, but still I consider it a great course. Having already done CAPE - nothing surprised me that much.

**Pros:**
- Inexpensive
- Materials are for life and updated
- Great teacher

**Cons:**
- Not that much recognized
- Not that much new stuff compared to CRTP

### HackTheBox: CWES
I've never been that interested in web exploitation, but since I finished the course path on HackTheBox Academy (*which is the best learning source imho*) I decided to give the exam a shot. Generally speaking - it is a beginner-friendly course for web exploitation. It teaches you the **fundamentals of web exploitation**, like SQL injection, XSS, CSRF, etc. These fundamentals will be useful for HackTheBox machines - if you play them. The only downside (at the time that I've done it) was there was a bit too much PHP, and a lack of other technologies covered.

**Pros:**
- Inexpensive
- Great course for beginners
- Web fundamentals are useful for HackTheBox machines

**Cons:**
- A bit too much of PHP
- Not that much recognized

### OffSec: OSCP
OSCP is one of the **most recognized certifications** in the industry (probably next to CISSP). I did it because I had the opportunity and it is always good to have OSCP on your resume. Since I had already completed three HTB certifications at that time - I was confident to finish it without a course. I cannot speak about the course itself, but the exam was **proctored, challenging and rewarding**. Good to be OSCP-certified.

**Pros:**
- Most recognized certification in the industry
- Practical
- OSCP does not expire

**Cons:**
- OSCP+ expires
- Expensive
- Losing its legendary status in recent years (my opinion)

## Conclusion

Looking back at this list, I realize how much the **journey itself** shaped my thinking — not just the certificates at the end of it.

If I had to give one piece of advice: don't chase certifications for the badge. **Chase them for the gaps they fill.** Security+ was right for where I was in 2022. CAPE was right for where I wanted to go in 2025. The order matters, and so does the intent.

A few things I've learned along the way:

- **Practical > theoretical.** Every time. If the exam doesn't involve actually breaking or building something, its value is limited.
- **Blue teamers should go red.** Not to switch sides, but to understand what you're defending against. CPTS changed how I think about detections more than any blue team course ever did.
- **Expensive doesn't mean better.** SANS is excellent, but so is HackTheBox Academy at a fraction of the cost. Know what you're paying for.
- **Recognition is overrated — until it isn't.** OSCP still opens doors. CAPE is getting there. But at the end of the day, *what matters is what you can actually do*.

*Still a few things on the list. The journey continues.*
