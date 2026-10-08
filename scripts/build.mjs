import { mkdir, copyFile } from "node:fs/promises";

await mkdir("dist/vendor", { recursive: true });
for (const file of [
  "index.html",
  "styles.css",
  "app.js",
  "totp.js",
  "CNAME",
  "favicon.svg",
]) {
  await copyFile(file, `dist/${file}`);
}
await copyFile(
  "node_modules/qrcode-generator/dist/qrcode.mjs",
  "dist/vendor/qrcode.mjs",
);
await copyFile("THIRD_PARTY_LICENSES", "dist/vendor/LICENSE");
