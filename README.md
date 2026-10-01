# GP Web Connect — MVP

Web app kecil (Go, satu binary, tanpa dependency) untuk menguji apakah GlobalProtect CLI di server headless bisa tersambung ke `sasa.telkomsel.co.id` dengan login SAML di browser laptop: URL login ditangkap server, callback `globalprotectcallback:...` di-paste manual, lalu diteruskan ke `globalprotect defaultbrowser` (GP 6.1.x tidak punya `launch-uri`; callback ditulis ke `~/GP_HTML/defaultbrowser/resp.html` dan dibaca PanGPA, jadi proses `connect` harus tetap hidup → pakai mode `keep`).

## Build

```sh
go test ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o gp-web .
```

## Konfigurasi (env)

| Env | Default |
| --- | --- |
| `GP_BIN` | `/usr/bin/globalprotect` |
| `GP_PORTAL` | `sasa.telkomsel.co.id` |
| `GP_REACH_HOSTS` | `cicd-gitlab-ee.telkomsel.co.id:443` (dipisah koma) |
| `GP_PORT` | `8080` (selalu bind ke `127.0.0.1`) |
| `GP_WEB_DIR` | `~/.gp-web` (`login-url`, `connect.log`) |
| `BROWSER` | `$GP_WEB_DIR/capture-url.sh` (diteruskan ke proses `connect`) |

## Setup server (sebagai user pemilik sesi GlobalProtect, bukan root)

```sh
sudo apt install xdg-utils libglib2.0-bin
sudo loginctl enable-linger "$USER"

mkdir -p ~/.gp-web ~/.local/share/applications ~/.config/systemd/user
cp deploy/capture-url.sh ~/.gp-web/ && chmod +x ~/.gp-web/capture-url.sh
sed "s|<user>|$USER|" deploy/gp-capture.desktop > ~/.local/share/applications/gp-capture.desktop
xdg-settings set default-web-browser gp-capture.desktop
```

### Pre-check H1 (sebelum pakai web app)

```sh
globalprotect disconnect; timeout 5 globalprotect show --status   # harus Disconnected
BROWSER=~/.gp-web/capture-url.sh globalprotect connect --portal sasa.telkomsel.co.id
cat ~/.gp-web/login-url    # harus URL https://, buka di browser laptop → halaman SSO
```

Kalau file kosong dan muncul "There is not default browser", telusuri dengan `strace -f -e trace=execve globalprotect connect ...`.

Catatan GP 6.1.4 (hasil uji di server):
- `gpshow.sh` hanya memanggil `xdg-open` kalau `$DISPLAY` mengandung `:`. Unit service men-set `DISPLAY=:0` (tidak perlu X server); untuk pre-check manual tambahkan `DISPLAY=:0`.
- Yang di-capture bukan URL https, tapi file lokal `~/GP_HTML/saml.html` (form POST auto-submit ke cloud-auth). Web app menyajikannya di `/saml-login`.
- Tidak ada `launch-uri`. Callback dikirim lewat `globalprotect defaultbrowser <uri>` (handler `globalprotectcallback:` di paket UI), yang menulis `~/GP_HTML/defaultbrowser/resp.html`; PanGPA membacanya via inotify. Proses `connect` harus tetap hidup → pakai mode `keep`.
- CLI menolak jalan ("already established ...") selama ada proses `globalprotect` lain milik user yang sama, atau selama daemon masih di state "Retrieving configuration...".
- Kalau `connect` dimatikan sebelum login selesai (Disconnect saat WAITING_CALLBACK, mode `stop-first`), daemon bisa nyangkut di "Retrieving configuration..." dan semua `connect` berikutnya ditolak. Pulihkan dengan `sudo systemctl restart gpd && systemctl --user restart gpa`.

### Jalankan web app

```sh
cp gp-web ~/.gp-web/gp-web
cp deploy/gp-web.service ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now gp-web
journalctl --user -u gp-web -f
```

Dari laptop: `gcloud compute ssh testing-gp -- -L 8080:localhost:8080`, lalu buka <http://localhost:8080>.
Kalau SSH putus setelah VPN naik, pakai `gcloud compute connect-to-serial-port testing-gp`.
Kembalikan default browser: `xdg-settings set default-web-browser firefox-esr.desktop`.

## Alur pemakaian

1. **Connect** → server spawn `globalprotect connect --portal ...` (process group sendiri), URL login muncul sebagai link.
2. Buka link di laptop, login SSO, klik kanan "click here" → Copy link.
3. Paste ke textarea, pilih mode, **Submit** dalam ±60 detik.
   - `keep`: proses `connect` dibiarkan hidup (mengulang percobaan manual).
   - `stop-first`: `connect` dikirim SIGINT dan ditunggu maks 3 detik dulu. **Jangan dipakai di GP 6.1.x**: PanGPA butuh sesi `connect` yang masih hidup.
4. Cek baris status: `gpStatus` Connected, interface `gpd*`/`tun*`, reach OK.

## API

| Method & path | Keterangan |
| --- | --- |
| `GET /` | halaman UI |
| `POST /api/connect` | `202 {state}`; `409` kalau state bukan IDLE/FAILED atau operasi lain sedang jalan |
| `GET /api/login-url` | `{state, url}` (`url:null` kalau belum ada) |
| `POST /api/callback` | body `{uri, mode}` → `{exitCode, stdout, stderr, state, connectStopped?}` |
| `GET /api/status` | `{state, gpStatus, iface, connectAlive, reach:[{host, ok}]}` |
| `POST /api/disconnect` | `{exitCode, stdout, stderr}`; state → IDLE |
| `GET /api/logs` | `{lines}`: 200 baris terakhir `connect.log` + hasil command terakhir |

State: `IDLE → CONNECTING → WAITING_CALLBACK → SUBMITTING → CONNECTED | FAILED`. `CONNECTED`/`FAILED` ditentukan dari exit code `defaultbrowser`; bukti sebenarnya ada di `/api/status`.

## Keamanan

- Command dijalankan dengan `exec.CommandContext` dan argumen terpisah (tanpa shell), dengan timeout (`show --status` 5s, `defaultbrowser` 30s, `disconnect` 15s).
- Hanya PID `connect` yang di-spawn server yang di-signal (tidak ada `pkill`).
- `token=`, `prelogin-cookie=`, `portal-userauthcookie=` di-redact sebelum masuk `connect.log`, log server, dan respons; URI callback tidak pernah ditulis ke disk.
- Bind `127.0.0.1` saja; request dengan `Host` non-loopback ditolak dan POST wajib `Content-Type: application/json` (proteksi DNS-rebinding/CSRF).

## Uji lokal tanpa GlobalProtect

```sh
GP_BIN=$PWD/testdata/fake-globalprotect.sh GP_WEB_DIR=/tmp/gpw BROWSER=/tmp/gpw/capture.sh go run .
```
(`/tmp/gpw/capture.sh` harus menulis `$1` ke `/tmp/gpw/login-url`.) Callback yang mengandung `expired` mensimulasikan token kedaluwarsa.

## Rencana tes (isi di server)

| # | Skenario | Diharapkan | Aktual |
| --- | --- | --- | --- |
| 1 | Pre-check H1: klik Connect | URL login ≤ 10 detik | OK: ±3 detik, setelah `DISPLAY=:0` + `/saml-login` (2026-10-01) |
| 2 | H2+H3 mode `keep` | Connected, atau "already established" | OK via `defaultbrowser`: Connected, `gpd0` UP, reach OK (2026-10-01) |
| 3 | H2+H3 mode `stop-first` | Connected | Tidak berlaku di 6.1.4: `connect` mati → daemon nyangkut |
| 4 | Token kedaluwarsa (> 60 detik) | error di PanGPA.log, state FAILED, server sehat | |
| 5 | Disconnect saat Connected | Disconnected, interface hilang | |
| 6 | Reconnect (#3 setelah #5) | Connected tanpa restart `gpd` | |
