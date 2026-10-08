# Family signal

A static site for creating a shared family TOTP token, intended for `https://totp.jasiek.me` on GitHub Pages. Each trusted person imports the same QR code into an authenticator such as Authy. During a call, one person reads their current code and the other compares it with their own app.

## Development

Requires Node.js 24 or newer, npm, and Python 3 for the local preview.

```sh
npm ci --ignore-scripts
npm test
npm run dev
```

Open `http://127.0.0.1:4173`. `npm run build` assembles the static files in `dist/`, including the pinned QR library and its license. Nothing loads from a CDN. Serve over HTTPS in production; localhost is also a secure context for Web Crypto.

## How enrollment works

- A click generates 20 random bytes using `crypto.getRandomValues`.
- The QR encodes a standard `otpauth://totp/` URI, using unpadded Base32, HMAC-SHA-1, six digits, and a 30-second period. Both the issuer prefix and issuer parameter are `totp.jasiek.me`. The user chooses a 1–64-character label; colons and control characters are rejected for URI compatibility.
- Web Crypto verifies two consecutive codes from the imported token, allowing one time step of clock drift in either direction. The same time step cannot complete both checks. If the next code is missed, verification can be restarted without replacing the secret.
- Each family member can repeat verification. Finishing clears secret references and displayed enrollment data, and overwrites the raw byte array. It cannot guarantee erasure of JavaScript-managed memory or a copied clipboard value.
- No backend, analytics, browser storage, or network requests carry the secret. The QR library is bundled locally. A restrictive content security policy blocks connections and external resources.

This is a shared-secret possession check, not proof of a specific person's identity. Anyone with the key can impersonate another group member, and codes can be relayed in real time. For suspicious requests, call back on a known number. Do not use codes from unrelated accounts. Authenticator cloud backup settings are outside this site's control.

## GitHub Pages

1. Push to `main` in a GitHub repository.
2. Under **Settings → Pages → Build and deployment**, select **GitHub Actions**.
3. Set the custom domain to **totp.jasiek.me** in Pages settings (the `CNAME` file alone does not configure a custom-workflow deployment).
4. Configure the DNS CNAME for `totp` to point to the repository owner's `<owner>.github.io` hostname. Enable **Enforce HTTPS** once GitHub provisions the certificate.

The workflow tests and builds pull requests; pushes to `main` also deploy `dist/` using the official Pages actions.

## Validation and references

`npm test` covers RFC 4648 Base32 vectors, RFC 4226 HOTP vectors, all SHA-1 RFC 6238 TOTP test vectors, URI encoding, the drift window, and two-code replay/expiry behavior. An authenticator app on a physical phone should also be checked before relying on an enrollment.

- [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html)
- [Authenticator key URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
- [GitHub Pages custom workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)
- [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) (MIT)
