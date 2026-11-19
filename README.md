# 🔐 Security Writeups & Notes

A personal knowledge base of vulnerabilities, CTF challenges, and security
research I find interesting. Everything here is from **lab environments I built**,
**CTF competitions**, or **authorized assessments** — anonymized so no real
target, client, or employer is identifiable.

> ⚠️ **Ethics & scope.** All testing described here was performed against systems
> I own or was explicitly authorized to test. Nothing in this repository should
> be used against systems you do not have permission to test. Techniques are
> shared for defensive education only.

## 📁 Structure

```
.
├── writeups/        # One markdown file per finding / challenge
├── assets/          # Screenshots, PoC scripts, diagrams
└── README.md        # This index
```

## 🗂️ Index

| Date | Title | Class | Difficulty |
|------|-------|-------|------------|
| 2026-11 | [Stored XSS via an unauthenticated ingest API](writeups/2026-11-stored-xss-via-unauth-ingest-api.md) | Stored XSS + Broken Access Control | ⭐⭐⭐ |
| 2026-11 | [OmegaSector — host spoofing → unrestricted file write → non-alphanumeric RCE](writeups/2026-11-omega-sector-host-spoofing-to-rce.md) | Auth Bypass + File Upload → RCE | ⭐⭐⭐⭐ |

## 🏷️ Tags

`#xss` `#broken-access-control` `#django` `#drf` `#web` `#api`
`#rce` `#file-upload` `#auth-bypass` `#parse-url` `#non-alphanumeric-php` `#php` `#ctf`

---

*Maintained for learning. Findings are sanitized; code samples are reconstructed
to illustrate the pattern, not copied from any proprietary source.*
