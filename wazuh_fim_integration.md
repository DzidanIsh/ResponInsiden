# Panduan Integrasi Wazuh Menggunakan FIM untuk Mendeteksi dan Merespons Web Defacement

## Gambaran Umum

Dokumen ini menjelaskan cara mengintegrasikan sistem anti-defacement dengan Wazuh menggunakan modul File Integrity Monitoring (FIM). Integrasi ini memungkinkan deteksi perubahan file secara real-time dan memicu respons otomatis berupa restore konten web dari backup jika terdeteksi perubahan mencurigakan.

## Prasyarat

- Wazuh Manager telah terpasang dan berjalan
- Wazuh Agent terpasang di server web
- Sistem backup dan restore anti-defacement telah terpasang
- Akses root pada server Wazuh Manager dan server web (Agent)

## Arsitektur Sistem

Integrasi ini menggunakan arsitektur sebagai berikut:

1. **Server Web dengan Wazuh Agent**:
   - Melakukan monitoring file web server (FIM)
   - Menjalankan script active response (`web_restore.sh`)
   - Memiliki sistem anti-defacement yang terinstall

2. **Server Monitoring dengan Wazuh Manager**:
   - Menerima event dari Wazuh Agent
   - Menganalisis event berdasarkan aturan kustom
   - Memicu active response pada Agent jika terdeteksi defacement
   - Menyimpan backup dari web server

## Metode Integrasi

Integrasi dilakukan dengan dua script utama:

1. **wazuh_agent_setup.sh**: Mengkonfigurasi Wazuh Agent pada server web
2. **wazuh_manager_setup.sh**: Mengkonfigurasi Wazuh Manager pada server monitoring

## Langkah-Langkah Integrasi Detail

### A. Konfigurasi pada Server Web (Wazuh Agent)

#### 1. Persiapan Awal

1. Pastikan Wazuh Agent dan sistem anti-defacement sudah terinstall
2. Unduh script integrasi ke server web:
   ```bash
   wget https://example.com/wazuh_agent_setup.sh
   chmod +x wazuh_agent_setup.sh
   ```

#### 2. Menjalankan Script Setup untuk Agent

1. Jalankan script dengan hak akses root:
   ```bash
   sudo ./wazuh_agent_setup.sh
   ```

2. Script akan melakukan pemeriksaan prasyarat:
   - Verifikasi Wazuh Agent terinstall dan berjalan
   - Verifikasi sistem anti-defacement terinstall
   - Identifikasi direktori web server dari konfigurasi

#### 3. Konfigurasi File Integrity Monitoring (FIM)

Script akan mengkonfigurasi FIM dengan menambahkan entri berikut ke `/var/ossec/etc/ossec.conf`:

```xml
<syscheck>
  <directories check_all="yes" realtime="yes" report_changes="yes">/var/www/html</directories>
  <ignore>/var/www/html/logs</ignore>
  <ignore>/var/www/html/cache</ignore>
  <ignore>/var/www/html/tmp</ignore>
  <ignore type="sregex">\.log$|\.tmp$</ignore>
  <frequency>43200</frequency>
  <scan_on_start>yes</scan_on_start>
</syscheck>
```

Pada tahap ini, Anda dapat mengkustomisasi direktori dan file yang diabaikan:
- Anda akan diminta apakah ada direktori khusus yang ingin diabaikan
- Anda dapat menentukan ekstensi file yang ingin diabaikan

#### 4. Pembuatan Script Active Response

Script akan membuat file active response di `/var/ossec/active-response/bin/web_restore.sh`:

```bash
#!/bin/bash

# Script Active Response untuk menjalankan restore
LOG_FILE="/var/log/wazuh-web-restore.log"

# Fungsi log
log() {
    echo "$(date) - $1" >> "$LOG_FILE"
}

# Catat waktu eksekusi dan alert
log "Web defacement terdeteksi - Memulai proses restore"

# Ekstrak data alert jika tersedia
if [ ! -z "$1" ]; then
    log "Alert data: $1"
fi

# Jalankan script restore
/usr/local/bin/web-restore --auto >> "$LOG_FILE" 2>&1

# Catat hasil
if [ $? -eq 0 ]; then
    log "Restore berhasil diselesaikan"
    exit 0
else
    log "Restore gagal"
    exit 1
fi
```

### B. Konfigurasi pada Server Monitoring (Wazuh Manager)

#### 1. Persiapan Awal

1. Pastikan Wazuh Manager sudah terinstall dan berjalan
2. Unduh script integrasi ke server Wazuh Manager:
   ```bash
   wget https://example.com/wazuh_manager_setup.sh
   chmod +x wazuh_manager_setup.sh
   ```

#### 2. Menjalankan Script Setup untuk Manager

1. Jalankan script dengan hak akses root:
   ```bash
   sudo ./wazuh_manager_setup.sh
   ```

2. Script akan melakukan pemeriksaan prasyarat:
   - Verifikasi Wazuh Manager terinstall dan berjalan
   - Persiapan direktori rules jika belum ada

#### 3. Pembuatan Custom Rules

Script akan membuat file aturan kustom di `/var/ossec/etc/rules/web_defacement_rules.xml`:

```xml
<!-- Aturan Kustom untuk Deteksi Web Defacement -->
<group name="web,defacement,">
  <!-- Rule dasar untuk perubahan file di direktori web -->
  <rule id="100500" level="10">
    <if_group>syscheck</if_group>
    <regex type="pcre2">^/var/www/html|^/srv/www|^/var/www</regex>
    <regex>modified|added</regex>
    <description>Perubahan terdeteksi pada file web</description>
  </rule>
  
  <!-- Rule untuk penambahan file mencurigakan di direktori web -->
  <rule id="100501" level="12" frequency="3" timeframe="300">
    <if_sid>100500</if_sid>
    <regex>\.php$|\.html$|\.js$|\.htaccess$</regex>
    <description>Kemungkinan defacement: Beberapa file web penting dimodifikasi</description>
  </rule>
  
  <!-- Rule untuk perubahan pada file indeks utama -->
  <rule id="100502" level="14">
    <if_sid>100500</if_sid>
    <match>index.php|index.html</match>
    <description>Halaman utama website dimodifikasi - Kemungkinan defacement!</description>
  </rule>
  
  <!-- Rule untuk penambahan file eksekusi skrip berbahaya -->
  <rule id="100503" level="14">
    <if_sid>100500</if_sid>
    <regex>\.php$|\.cgi$|\.pl$</regex>
    <match>added</match>
    <description>File skrip baru ditambahkan ke direktori web - Kemungkinan backdoor!</description>
  </rule>
</group>
```

Anda dapat menyesuaikan tingkat sensitivitas aturan ini dengan memilih opsi:
- Sensitivitas rendah: Mengurangi false positives
- Sensitivitas sedang: Default
- Sensitivitas tinggi: Lebih sensitif terhadap perubahan

#### 4. Konfigurasi Local Decoder (Opsional)

Script akan membuat atau memperbarui `/var/ossec/etc/local_decoder.xml` jika diperlukan:

```xml
<!-- Local Decoders -->
<decoder_list>
  <!-- Decoder untuk mendeteksi perubahan pada file web -->
  <decoder name="web-defacement">
    <prematch>^ossec: File integrity monitoring event</prematch>
    <regex offset="after_prematch">Integrity checksum changed for: '(\S+)'</regex>
    <order>file</order>
  </decoder>
</decoder_list>
```

#### 5. Konfigurasi Agent Centralized

Script membuat konfigurasi yang akan didistribusikan ke agent di `/var/ossec/etc/shared/default/agent.conf`:

```xml
<agent_config>
  <!-- Active Response configuration for web anti-defacement -->
  <active-response>
    <command>web-restore</command>
    <location>local</location>
    <rules_id>100501,100502,100503</rules_id>
    <timeout>60</timeout>
  </active-response>
</agent_config>
```

#### 6. Konfigurasi Command di Manager

Script menambahkan definisi command ke `/var/ossec/etc/ossec.conf`:

```xml
<!-- Command definition for web anti-defacement -->
<command>
  <name>web-restore</name>
  <executable>web_restore.sh</executable>
  <expect>srcip</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

#### 7. Konfigurasi Notifikasi Email (Opsional)

Anda akan ditanya apakah ingin mengaktifkan notifikasi email untuk alert:
- Jika ya, Anda akan diminta untuk memasukkan alamat email penerima
- Anda juga dapat mengkonfigurasi server SMTP

### C. Memverifikasi Integrasi

Setelah konfigurasi selesai, jalankan langkah-langkah berikut untuk memverifikasi integrasi:

#### 1. Periksa Status Agen

Di server Wazuh Manager:
```bash
sudo /var/ossec/bin/agent_control -l
```

Pastikan agent terdaftar dan aktif.

#### 2. Periksa Konfigurasi Syscheck

Di server web:
```bash
sudo grep -A 20 "<syscheck>" /var/ossec/etc/ossec.conf
```

Pastikan direktori web yang benar sedang dipantau dengan realtime="yes".

#### 3. Periksa Konfigurasi Active Response

Di server web:
```bash
sudo ls -la /var/ossec/active-response/bin/web_restore.sh
sudo cat /var/ossec/active-response/bin/web_restore.sh
```

Pastikan script memiliki izin eksekusi.

#### 4. Periksa Custom Rules

Di server Wazuh Manager:
```bash
sudo cat /var/ossec/etc/rules/web_defacement_rules.xml
```

Pastikan aturan dikonfigurasi dengan benar.

#### 5. Uji Integrasi

Untuk menguji apakah integrasi berfungsi dengan benar:

1. Di server web, buat perubahan mencurigakan pada file web:
   ```bash
   sudo echo "Hacked!" > /var/www/html/index.html
   ```

2. Di server Wazuh Manager, amati log alert:
   ```bash
   sudo tail -f /var/ossec/logs/alerts/alerts.log
   ```

3. Di server web, periksa log active response:
   ```bash
   sudo tail -f /var/log/wazuh-web-restore.log
   ```

4. Verifikasi bahwa restore dilakukan:
   ```bash
   sudo cat /var/www/html/index.html
   ```
   Isi file seharusnya kembali ke konten asli setelah beberapa detik.

## Penyesuaian Lanjutan

### 1. Penyesuaian Sensitivitas Deteksi

Untuk menyesuaikan sensitivitas deteksi, ubah parameter berikut di file rules:

- **Frekuensi Trigger**: Parameter `frequency` pada rule ID 100501
- **Level Alert**: Parameter `level` pada rule
- **Timeframe**: Parameter `timeframe` pada rule (dalam detik)

### 2. Pengecualian Tambahan

Untuk mengecualikan direktori atau file tambahan dari pemantauan:

1. Edit file konfigurasi agent:
   ```bash
   sudo vi /var/ossec/etc/ossec.conf
   ```

2. Tambahkan entri `<ignore>` di bawah bagian `<syscheck>`:
   ```xml
   <ignore>/path/to/directory</ignore>
   <ignore type="sregex">pattern_to_ignore</ignore>
   ```

3. Restart Wazuh Agent:
   ```bash
   sudo systemctl restart wazuh-agent
   ```

### 3. Kustomisasi Active Response

Jika Anda ingin memodifikasi perilaku active response:

1. Edit script active response:
   ```bash
   sudo vi /var/ossec/active-response/bin/web_restore.sh
   ```

2. Lakukan perubahan yang diinginkan, misalnya:
   - Menambahkan notifikasi tambahan
   - Menambahkan validasi sebelum melakukan restore
   - Menyimpan backup file yang dimodifikasi

3. Pastikan script tetap memiliki izin eksekusi:
   ```bash
   sudo chmod +x /var/ossec/active-response/bin/web_restore.sh
   ```

## Pemecahan Masalah

### Wazuh Agent

#### Agent Tidak Mengirim Alert

1. Periksa status koneksi agent:
   ```bash
   sudo /var/ossec/bin/agent_control -l
   ```

2. Periksa konfigurasi syscheck:
   ```bash
   sudo grep -A 20 "<syscheck>" /var/ossec/etc/ossec.conf
   ```

3. Periksa log agent:
   ```bash
   sudo tail -f /var/ossec/logs/ossec.log
   ```

4. Pastikan agent telah di-restart setelah perubahan konfigurasi:
   ```bash
   sudo systemctl restart wazuh-agent
   ```

#### Active Response Tidak Berjalan

1. Periksa izin file script:
   ```bash
   sudo ls -la /var/ossec/active-response/bin/web_restore.sh
   ```

2. Periksa log active response:
   ```bash
   sudo tail -f /var/log/wazuh-web-restore.log
   ```

3. Coba jalankan script manual untuk memverifikasi:
   ```bash
   sudo /var/ossec/active-response/bin/web_restore.sh
   ```

4. Periksa apakah script restore anti-defacement dapat dijalankan:
   ```bash
   sudo /usr/local/bin/web-restore --auto
   ```

### Wazuh Manager

#### Alert Tidak Terpicu

1. Periksa apakah event syscheck diterima:
   ```bash
   sudo tail -f /var/ossec/logs/archives/archives.log | grep syscheck
   ```

2. Periksa konfigurasi aturan kustom:
   ```bash
   sudo cat /var/ossec/etc/rules/web_defacement_rules.xml
   ```

3. Periksa log manager:
   ```bash
   sudo tail -f /var/ossec/logs/ossec.log
   ```

4. Pastikan manager telah di-restart setelah perubahan konfigurasi:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

#### Konfigurasi Agent Tidak Terdistribusi

1. Periksa apakah file agent.conf ada dan valid:
   ```bash
   sudo cat /var/ossec/etc/shared/default/agent.conf
   ```

2. Perbarui agent dengan konfigurasi baru secara manual:
   ```bash
   # Di server Agent
   sudo /var/ossec/bin/agent_control -r -a
   ```

## Pemeliharaan Rutin

### Monitoring Log

Periksa log secara berkala untuk memastikan sistem berfungsi dengan baik:

```bash
# Log Wazuh Manager
sudo tail -f /var/ossec/logs/ossec.log

# Log alert
sudo tail -f /var/ossec/logs/alerts/alerts.log

# Log active response
sudo tail -f /var/log/wazuh-web-restore.log
```

### Pengujian Berkala

Lakukan pengujian secara berkala untuk memastikan sistem merespons dengan benar:

1. Buat perubahan kecil pada file web (yang tidak disengaja merusak)
2. Verifikasi bahwa alert terpicu
3. Verifikasi bahwa active response dijalankan
4. Verifikasi bahwa file dikembalikan ke kondisi normal

### Update Aturan

Perbarui aturan secara berkala untuk meningkatkan deteksi atau mengurangi false positives:

1. Edit file aturan kustom:
   ```bash
   sudo vi /var/ossec/etc/rules/web_defacement_rules.xml
   ```

2. Restart Wazuh Manager setelah perubahan:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

## Referensi

- [Dokumentasi Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Dokumentasi Wazuh Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)
- [Dokumentasi Wazuh Custom Rules](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html)
- [Dokumentasi Centralized Configuration](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html) 