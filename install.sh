#!/bin/bash

# Script Instalasi untuk Sistem Backup, Restore, Containment, dan Eradication Web Server
# BAGIAN INSTALASI
# ------------------------------------------------------------------------------------

# Fungsi untuk menampilkan pesan error dan keluar
error_exit() {
    echo -e "\e[31m[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1\e[0m"
    exit 1
}

# Fungsi untuk menampilkan pesan sukses
success_msg() {
    echo -e "\e[32m[SUCCESS] $(date '+%Y-%m-%d %H:%M:%S') - $1\e[0m"
}

# Fungsi untuk menampilkan pesan info
info_msg() {
    echo -e "\e[34m[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1\e[0m"
}

# Fungsi untuk menampilkan pesan peringatan
warning_msg() {
    echo -e "\e[33m[WARNING] $(date '+%Y-%m-%d %H:%M:%S') - $1\e[0m"
}

# Banner
echo "================================================================="
echo "      INSTALASI SISTEM KEAMANAN WEB SERVER (ANTI-DEFACEMENT)     "
echo "================================================================="
echo ""

# 1. Verifikasi Sistem dan Dependensi Awal
# ------------------------------------------
info_msg "Memulai verifikasi sistem dan dependensi awal..."

if [ "$(id -u)" -ne 0 ]; then
    error_exit "Script ini harus dijalankan sebagai root atau dengan sudo."
fi

if ! command -v apt-get &> /dev/null; then
    error_exit "Sistem operasi tidak didukung (hanya Debian/Ubuntu dengan apt-get)."
fi

info_msg "Melakukan update daftar paket (apt-get update)..."
apt-get update -y || warning_msg "Gagal melakukan apt-get update, proses instalasi dilanjutkan."

REQUIRED_CMDS=("git" "python3" "curl" "pip3" "rsync") # Menambahkan rsync
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        info_msg "$cmd tidak ditemukan. Mencoba menginstal..."
        if [[ "$cmd" == "pip3" ]]; then
            apt-get install -y python3-pip || error_exit "Gagal menginstal python3-pip."
        elif [[ "$cmd" == "python3" ]]; then
             apt-get install -y python3 python3-venv python3-pip || error_exit "Gagal menginstal python3."
        else
            apt-get install -y "$cmd" || error_exit "Gagal menginstal $cmd."
        fi
        success_msg "$cmd berhasil diinstal."
    else
        info_msg "$cmd sudah terinstal."
    fi
done

# 2. Pengumpulan Informasi Konfigurasi
# -------------------------------------
info_msg "Memulai pengumpulan informasi konfigurasi..."
CONFIG_DIR="/etc/web-backup"
mkdir -p "$CONFIG_DIR" || error_exit "Gagal membuat direktori konfigurasi $CONFIG_DIR"

# Konfigurasi Direktori Web & Pengguna/Grup Web Server
read -r -p "Masukkan path direktori web server (default: /var/www/html): " WEB_DIR
WEB_DIR=${WEB_DIR:-/var/www/html}
if [[ ! -d "$WEB_DIR" ]]; then
    mkdir -p "$WEB_DIR" || error_exit "Gagal membuat direktori $WEB_DIR."
    info_msg "Direktori $WEB_DIR telah dibuat."
fi

read -r -p "Masukkan nama pengguna web server (cth: www-data, apache, default: www-data): " WEB_SERVER_USER
WEB_SERVER_USER=${WEB_SERVER_USER:-www-data}
read -r -p "Masukkan nama grup web server (cth: www-data, apache, default: www-data): " WEB_SERVER_GROUP
WEB_SERVER_GROUP=${WEB_SERVER_GROUP:-www-data}

id "$WEB_SERVER_USER" &>/dev/null || warning_msg "Pengguna web server '$WEB_SERVER_USER' tidak ditemukan. Pastikan pengguna ini ada."
getent group "$WEB_SERVER_GROUP" &>/dev/null || warning_msg "Grup web server '$WEB_SERVER_GROUP' tidak ditemukan. Pastikan grup ini ada."


# Konfigurasi Server Monitoring
read -r -p "Masukkan IP Server Monitoring (default: 192.168.92.10): " MONITOR_IP
MONITOR_IP=${MONITOR_IP:-192.168.92.10}

read -r -p "Masukkan Username SSH di Server Monitoring (default: wazuh): " MONITOR_USER
MONITOR_USER=${MONITOR_USER:-wazuh}

read -r -p "Masukkan Path Direktori Backup Git di Server Monitoring (default: /var/backup/web): " REMOTE_GIT_BACKUP_PATH
REMOTE_GIT_BACKUP_PATH=${REMOTE_GIT_BACKUP_PATH:-/var/backup/web}

# Konfigurasi Backup File Dinamis
info_msg "Konfigurasi Backup File Dinamis..."
read -r -p "Aktifkan backup untuk file/direktori dinamis (y/n, default: y): " ENABLE_DYNAMIC_BACKUP
ENABLE_DYNAMIC_BACKUP=${ENABLE_DYNAMIC_BACKUP:-y}
BACKUP_DYNAMIC="false"
if [[ "$ENABLE_DYNAMIC_BACKUP" == "y" || "$ENABLE_DYNAMIC_BACKUP" == "Y" ]]; then
    BACKUP_DYNAMIC="true"
fi

read -r -p "Masukkan path direktori staging lokal untuk backup dinamis (default: /var/tmp/web_dynamic_staging): " LOCAL_DYNAMIC_STAGING_DIR
LOCAL_DYNAMIC_STAGING_DIR=${LOCAL_DYNAMIC_STAGING_DIR:-/var/tmp/web_dynamic_staging}
mkdir -p "$LOCAL_DYNAMIC_STAGING_DIR" || error_exit "Gagal membuat direktori $LOCAL_DYNAMIC_STAGING_DIR."

read -r -p "Masukkan path direktori backup dinamis di Server Monitoring (default: ${REMOTE_GIT_BACKUP_PATH}/dynamic): " REMOTE_DYNAMIC_BACKUP_PATH
REMOTE_DYNAMIC_BACKUP_PATH=${REMOTE_DYNAMIC_BACKUP_PATH:-${REMOTE_GIT_BACKUP_PATH}/dynamic}

# Konfigurasi Restore File Dinamis
read -r -p "Masukkan path direktori cache lokal untuk restore dinamis (default: /var/tmp/web_dynamic_restore_cache): " LOCAL_DYNAMIC_RESTORE_CACHE_DIR
LOCAL_DYNAMIC_RESTORE_CACHE_DIR=${LOCAL_DYNAMIC_RESTORE_CACHE_DIR:-/var/tmp/web_dynamic_restore_cache}
mkdir -p "$LOCAL_DYNAMIC_RESTORE_CACHE_DIR" || error_exit "Gagal membuat direktori $LOCAL_DYNAMIC_RESTORE_CACHE_DIR."


# Konfigurasi Eradication
info_msg "Konfigurasi Eradication (Karantina, YARA, ClamAV)..."
read -r -p "Masukkan path direktori karantina (default: /var/quarantine/web): " QUARANTINE_DIR
QUARANTINE_DIR=${QUARANTINE_DIR:-/var/quarantine/web}
mkdir -p "$QUARANTINE_DIR" || error_exit "Gagal membuat direktori $QUARANTINE_DIR."

read -r -p "Masukkan path direktori YARA rules (default: /var/ossec/etc/rules/yara): " YARA_RULES_DIR
YARA_RULES_DIR=${YARA_RULES_DIR:-/var/ossec/etc/rules/yara}
# mkdir -p "$YARA_RULES_DIR" # Biarkan admin atau Wazuh yang membuat ini jika perlu.

read -r -p "Masukkan path ClamAV daemon socket (default: /var/run/clamav/clamd.ctl): " CLAMD_SOCKET
CLAMD_SOCKET=${CLAMD_SOCKET:-/var/run/clamav/clamd.ctl}

# Konfigurasi Containment (Rule ID untuk pemicu)
info_msg "Konfigurasi Containment (Rule ID Wazuh Pemicu)..."
read -r -p "Masukkan Rule ID Wazuh untuk Defacement (pisahkan dengan koma, contoh: 550,554): " DEFACE_RULE_IDS
DEFACE_RULE_IDS=${DEFACE_RULE_IDS:-"500550"}

read -r -p "Masukkan Rule ID Wazuh untuk Serangan Lain (pisahkan dengan koma): " ATTACK_RULE_IDS
ATTACK_RULE_IDS=${ATTACK_RULE_IDS:-"5710,5712,5715,5760,100003,100004"}

# Konfigurasi Pengguna dan Grup Wazuh (untuk Active Response)
info_msg "Konfigurasi Pengguna & Grup untuk Integrasi Wazuh Active Response..."
read -r -p "Masukkan nama pengguna Wazuh (yang menjalankan Active Response, default: wazuh): " WAZUH_USER
WAZUH_USER=${WAZUH_USER:-wazuh}
id "$WAZUH_USER" &>/dev/null || warning_msg "Pengguna Wazuh '$WAZUH_USER' tidak ditemukan. Pastikan pengguna ini ada jika menggunakan Active Response."

read -r -p "Masukkan nama grup utama pengguna Wazuh (default: wazuh): " WAZUH_GROUP
WAZUH_GROUP=${WAZUH_GROUP:-wazuh}
getent group "$WAZUH_GROUP" &>/dev/null || warning_msg "Grup Wazuh '$WAZUH_GROUP' tidak ditemukan."

read -r -p "Masukkan nama grup bersama untuk Active Response (agar Wazuh bisa akses web_dir, default: websecops): " SHARED_AR_GROUP
SHARED_AR_GROUP=${SHARED_AR_GROUP:-websecops}

# Konfigurasi Integrasi YETI (CTI)
info_msg "Konfigurasi Integrasi YETI (CTI)..."
read -r -p "Aktifkan integrasi dengan YETI (y/n, default: n): " ENABLE_YETI_INTEGRATION
ENABLE_YETI_INTEGRATION=${ENABLE_YETI_INTEGRATION:-n}
YETI_ENABLED="false"
YETI_API_URL=""
YETI_API_KEY=""

if [[ "$ENABLE_YETI_INTEGRATION" == "y" || "$ENABLE_YETI_INTEGRATION" == "Y" ]]; then
    YETI_ENABLED="true"
    read -r -p "Masukkan URL API YETI (contoh: https://yeti.domain.com/api/): " YETI_API_URL
    while [[ -z "$YETI_API_URL" ]]; do
        read -r -p "URL API YETI tidak boleh kosong. Masukkan URL API YETI: " YETI_API_URL
    done
    read -r -sp "Masukkan API Key YETI: " YETI_API_KEY_INPUT
    echo ""
    while [[ -z "$YETI_API_KEY_INPUT" ]]; do
        read -r -sp "API Key YETI tidak boleh kosong. Masukkan API Key YETI: " YETI_API_KEY_INPUT
        echo ""
    done
    YETI_API_KEY=$YETI_API_KEY_INPUT
fi

# Pengaturan Password Backup/Restore
info_msg "Pengaturan Password Backup dan Restore..."
BACKUP_PASSWORD=""
CONFIRM_PASSWORD=""
while true; do
    read -r -sp "Masukkan password untuk backup dan restore (minimal 8 karakter): " BACKUP_PASSWORD
    echo ""
    if [[ ${#BACKUP_PASSWORD} -lt 8 ]]; then
        warning_msg "Password terlalu pendek (minimal 8 karakter)."
        continue
    fi
    read -r -sp "Konfirmasi password: " CONFIRM_PASSWORD
    echo ""
    if [ "$BACKUP_PASSWORD" == "$CONFIRM_PASSWORD" ]; then
        break
    else
        warning_msg "Password tidak cocok! Silakan coba lagi."
    fi
done
ENCODED_PASSWORD=$(echo -n "$BACKUP_PASSWORD" | base64)

# Path Kunci SSH akan diatur di bagian 10 dan disimpan di sini
SSH_IDENTITY_FILE_PATH=""


# 3. Membuat File Konfigurasi /etc/web-backup/config.conf
# --------------------------------------------------------
info_msg "Membuat file konfigurasi $CONFIG_DIR/config.conf..."
# Inisialisasi variabel
DEFAULT_ERADICATION_PATTERNS=''
# Tambahkan setiap pola secara bertahap
DEFAULT_ERADICATION_PATTERNS+='(?i)(eval\s*\(base64_decode\s*\()|||'
DEFAULT_ERADICATION_PATTERNS+='(?i)(passthru\s*\()|||'
DEFAULT_ERADICATION_PATTERNS+='(?i)(shell_exec\s*\()|||'
DEFAULT_ERADICATION_PATTERNS+='(?i)(system\s*\()|||'
DEFAULT_ERADICATION_PATTERNS+='(?i)(exec\s*\()|||'
# Perhatikan bagian ini, ini adalah salah satu bagian yang kompleks
DEFAULT_ERADICATION_PATTERNS+='(?i)(preg_replace\s*\(.*\/e\s*\))|||'
DEFAULT_ERADICATION_PATTERNS+='(?i)(FilesMan|phpfm|P\.A\.S\.|\bWebShell\b|r57shell|c99shell)|||'
DEFAULT_ERADICATION_PATTERNS+='(?i)(document\.write\s*\(\s*unescape\s*\()|||'
DEFAULT_ERADICATION_PATTERNS+='(?i)(fsockopen|pfsockopen)\s*\('

# Sekarang Anda bisa menggunakan variabel DEFAULT_ERADICATION_PATTERNS
# Contoh:
# echo "$DEFAULT_ERADICATION_PATTERNS"


# Variabel SSH_IDENTITY_FILE_PATH akan diisi nanti di bagian 10
# dan kemudian ditambahkan ke file config.conf saat file tersebut ditulis ulang atau diperbarui
# Untuk sekarang, kita siapkan placeholder atau akan menuliskannya setelah kunci dibuat.

# (File config.conf akan ditulis ulang di akhir bagian 10 setelah SSH_IDENTITY_FILE_PATH didapatkan)

# 4. Instalasi Dependensi Sistem dan Python
# -----------------------------------------
info_msg "Memulai instalasi dependensi sistem dan Python..."

SYSTEM_PACKAGES=("clamav-daemon" "clamav-freshclam" "yara")
if ! dpkg -s "python3-magic" &> /dev/null; then
    if apt-cache show python3-magic &>/dev/null; then
        SYSTEM_PACKAGES+=("python3-magic")
    fi
fi

for pkg in "${SYSTEM_PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" &> /dev/null; then
        info_msg "Menginstal $pkg..."
        apt-get install -y "$pkg" || warning_msg "Gagal menginstal $pkg. Beberapa fungsionalitas mungkin terganggu."
    else
        info_msg "$pkg sudah terinstal."
    fi
done

PYTHON_LIBRARIES=("requests" "GitPython" "paramiko" "python-clamd" "yara-python")
if ! dpkg -s "python3-magic" &> /dev/null && ! pip3 list --format=freeze | grep -qi "python-magic"; then
    PYTHON_LIBRARIES+=("python-magic")
fi

info_msg "Menginstal library Python via pip3: ${PYTHON_LIBRARIES[*]}..."
pip3 install --upgrade pip
# shellcheck disable=SC2068
if pip3 install ${PYTHON_LIBRARIES[@]}; then
    success_msg "Library Python berhasil diinstal."
else
    warning_msg "Gagal menginstal satu atau lebih library Python. Beberapa fungsionalitas mungkin terganggu."
fi

if command -v freshclam &> /dev/null; then
    info_msg "Menjalankan freshclam untuk memperbarui database ClamAV (mungkin perlu beberapa saat)..."
    FRESHCLAM_SERVICE_ACTIVE=false
    if command -v systemctl &> /dev/null && systemctl is-active --quiet clamav-freshclam; then
        FRESHCLAM_SERVICE_ACTIVE=true
        systemctl stop clamav-freshclam
    fi
    
    freshclam || warning_msg "freshclam gagal. Anda mungkin perlu menjalankannya secara manual atau memperbaiki konfigurasi."
    
    if $FRESHCLAM_SERVICE_ACTIVE; then
        systemctl start clamav-freshclam
    fi

    if command -v systemctl &> /dev/null; then
        if ! systemctl is-active --quiet clamav-daemon; then
            info_msg "Mencoba menjalankan service clamav-daemon..."
            systemctl start clamav-daemon && systemctl enable clamav-daemon || warning_msg "Gagal memulai atau mengaktifkan clamav-daemon."
        else
            info_msg "Service clamav-daemon sudah berjalan."
        fi
    fi
else
    warning_msg "Perintah freshclam tidak ditemukan. Database ClamAV mungkin tidak terbaru."
fi


# 5. Mengunduh dan Menempatkan Skrip-Skrip Aplikasi
# -------------------------------------------------
info_msg "Mengunduh skrip-skrip aplikasi dari GitHub..."
TEMP_DIR="/tmp/web-security-setup-$(date +%s)"
mkdir -p "$TEMP_DIR" || error_exit "Gagal membuat direktori temporer $TEMP_DIR."
cd "$TEMP_DIR" || error_exit "Gagal masuk ke direktori temporer."

REPO_URL_BASE="https://raw.githubusercontent.com/DzidanIsh/ResponInsiden/main" # Ganti dengan URL Repo Anda

FILES_TO_DOWNLOAD=(
    "Backup/backup.sh /usr/local/bin web-backup root root"                 # Akan dimodifikasi di repo Anda
    "Backup/restore.py /usr/local/bin web-restore root root"             # Akan dimodifikasi di repo Anda (atau restore_auto.py)
    "Backup/restore_auto.py /usr/local/bin restore_auto.py root root"     # Akan dimodifikasi di repo Anda
    "Backup/containment.py /usr/local/bin containment.py root root"       # Akan dimodifikasi di repo Anda
    "Backup/eradication.py /usr/local/bin eradication.py root root"       # Akan dimodifikasi di repo Anda
    "Backup/maintenance.html $WEB_DIR maintenance.html $WEB_SERVER_USER $WEB_SERVER_GROUP"
)

download_from_github() {
    local file_path_in_repo="$1"
    local target_dir="$2"
    local target_filename="$3"
    local owner="${4:-root}"
    local group="${5:-root}"

    info_msg "Mengunduh $file_path_in_repo ke $target_dir/$target_filename..."
    mkdir -p "$target_dir"
    
    if curl -s -f -L -o "$target_dir/$target_filename" "$REPO_URL_BASE/$file_path_in_repo"; then
        success_msg "Berhasil mengunduh $file_path_in_repo."
        if [[ "$target_filename" != "maintenance.html" ]]; then # Hanya chmod +x untuk skrip
             chmod +x "$target_dir/$target_filename"
        else
             chmod 644 "$target_dir/$target_filename" # Izin baca untuk html
        fi
        if id "$owner" &>/dev/null && getent group "$group" &>/dev/null; then
            chown "$owner:$group" "$target_dir/$target_filename" || warning_msg "Gagal mengatur kepemilikan $owner:$group untuk $target_dir/$target_filename"
        else
            warning_msg "Pengguna '$owner' atau grup '$group' tidak valid. Kepemilikan $target_dir/$target_filename tidak diubah."
        fi
    else
        error_exit "Gagal mengunduh $file_path_in_repo dari GitHub. Pastikan URL REPO_URL_BASE dan path file benar."
    fi
}

for file_info in "${FILES_TO_DOWNLOAD[@]}"; do
    # shellcheck disable=SC2086
    download_from_github $file_info
done

# 6. Membuat dan Menyesuaikan Skrip Lokal (web-backup-dynamic)
# -------------------------------------------------------------
info_msg "Membuat skrip /usr/local/bin/web-backup-dynamic..."
cat > "/usr/local/bin/web-backup-dynamic" << 'EOF_DYNAMIC_BACKUP'
#!/bin/bash
set -euo pipefail

CONFIG_FILE="/etc/web-backup/config.conf"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [ERROR] File konfigurasi '$CONFIG_FILE' tidak ditemukan." >&2
    exit 1
fi
# shellcheck source=/dev/null
source "$CONFIG_FILE"

log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

if [ -z "${LOCAL_DYNAMIC_STAGING_DIR:-}" ] || ! mkdir -p "$LOCAL_DYNAMIC_STAGING_DIR"; then
    log_msg "[ERROR] LOCAL_DYNAMIC_STAGING_DIR tidak diset atau gagal dibuat: '$LOCAL_DYNAMIC_STAGING_DIR'." >&2
    exit 1
fi

if ! declare -p DYNAMIC_DIRS &>/dev/null || ! [[ "$(declare -p DYNAMIC_DIRS)" =~ "declare -a" ]]; then
    log_msg "[ERROR] DYNAMIC_DIRS tidak terdefinisi sebagai array di config.conf." >&2
    exit 1
fi
if [ ${#DYNAMIC_DIRS[@]} -eq 0 ]; then
    log_msg "[INFO] Tidak ada DYNAMIC_DIRS yang dikonfigurasi. Tidak ada file dinamis yang di-backup ke staging."
    exit 0
fi

log_msg "[INFO] Memulai backup file dinamis ke staging area: $LOCAL_DYNAMIC_STAGING_DIR"
for dir_name in "${DYNAMIC_DIRS[@]}"; do
    source_path="$WEB_DIR/$dir_name" 
    if [ -z "${WEB_DIR:-}" ]; then 
        log_msg "[ERROR] Variabel WEB_DIR tidak diset di config.conf." >&2
        exit 1
    fi
    if [ -d "$source_path" ] || [ -f "$source_path" ]; then
        archive_dir_name=$(echo "$dir_name" | tr '/' '_') # Ganti slash dengan underscore untuk nama file
        timestamp=$(date +%Y%m%d_%H%M%S)
        backup_name="${archive_dir_name}_${timestamp}.tar.gz"
        target_archive_path="$LOCAL_DYNAMIC_STAGING_DIR/$backup_name"
        
        log_msg "[INFO] Membuat arsip untuk '$dir_name' dari '$source_path' ke '$target_archive_path'..."
        # Menggunakan -C untuk mengubah direktori kerja tar sehingga path dalam arsip relatif
        if tar -czf "$target_archive_path" -C "$WEB_DIR" "$dir_name"; then
            log_msg "[SUCCESS] Arsip '$backup_name' berhasil dibuat."
        else
            log_msg "[ERROR] Gagal membuat arsip untuk '$dir_name'." >&2
        fi
    else
        log_msg "[WARNING] Direktori/file dinamis sumber '$source_path' tidak ditemukan."
    fi
done

log_msg "[INFO] Membersihkan arsip lama (lebih dari 1 hari) di staging area '$LOCAL_DYNAMIC_STAGING_DIR'..."
find "$LOCAL_DYNAMIC_STAGING_DIR" -type f -name "*.tar.gz" -mtime +0 -delete || \
    log_msg "[WARNING] Gagal membersihkan arsip lama di staging area."

log_msg "[INFO] Proses backup file dinamis ke staging selesai."
EOF_DYNAMIC_BACKUP

chmod +x "/usr/local/bin/web-backup-dynamic"
success_msg "Skrip /usr/local/bin/web-backup-dynamic berhasil dibuat."


# Verifikasi variabel penting setelah pengumpulan input dan sebelum penggunaan utama
# (Variabel ini ada di shell saat ini dari input pengguna)
REQUIRED_VARS_CHECK=(
    "WEB_DIR" "MONITOR_IP" "MONITOR_USER" "REMOTE_GIT_BACKUP_PATH"
    "WEB_SERVER_USER" "WEB_SERVER_GROUP" "WAZUH_USER" "WAZUH_GROUP" "SHARED_AR_GROUP"
    "LOCAL_DYNAMIC_STAGING_DIR" "REMOTE_DYNAMIC_BACKUP_PATH" "LOCAL_DYNAMIC_RESTORE_CACHE_DIR"
)
for var_check in "${REQUIRED_VARS_CHECK[@]}"; do
    if [ -z "${!var_check+x}" ] || [ -z "${!var_check}" ]; then
        error_exit "Variabel internal skrip instalasi '$var_check' tidak ditemukan atau kosong sebelum pembuatan config utama. Harap periksa input."
    fi
done

# 7. Pengaturan Git di Direktori Web Server
# -------------------------------------------
info_msg "Memulai pengaturan Git di direktori web: $WEB_DIR..."
cd "$WEB_DIR" || error_exit "Gagal masuk ke direktori $WEB_DIR."

read -r -p "Masukkan nama pengguna untuk commit Git di server web ini (default: webserver_backup): " GIT_COMMIT_USERNAME
GIT_COMMIT_USERNAME=${GIT_COMMIT_USERNAME:-webserver_backup}
read -r -p "Masukkan email untuk commit Git di server web ini (default: backup@$(hostname -f 2>/dev/null || hostname)): " GIT_COMMIT_EMAIL
GIT_COMMIT_EMAIL=${GIT_COMMIT_EMAIL:-backup@$(hostname -f 2>/dev/null || hostname)}

if [ -d ".git" ]; then
    read -r -p "Direktori .git sudah ada di $WEB_DIR. Apakah Anda ingin menghapus dan menginisialisasi ulang? (y/N): " REINIT_GIT
    REINIT_GIT=${REINIT_GIT:-N}
    if [[ "$REINIT_GIT" == "y" || "$REINIT_GIT" == "Y" ]]; then
        info_msg "Menghapus direktori .git yang sudah ada..."
        rm -rf .git || error_exit "Gagal menghapus .git direktori."
        git init || error_exit "Gagal menginisialisasi repository Git baru."
        success_msg "Repository Git berhasil diinisialisasi ulang."
    else
        info_msg "Menggunakan repository Git yang sudah ada."
    fi
else
    git init || error_exit "Gagal menginisialisasi repository Git."
    success_msg "Repository Git berhasil diinisialisasi."
fi

info_msg "Mengkonfigurasi Git user.name dan user.email secara lokal untuk repository ini..."
git config --local user.name "$GIT_COMMIT_USERNAME"
git config --local user.email "$GIT_COMMIT_EMAIL"

info_msg "Membuat file .gitignore default..."
cat > "$WEB_DIR/.gitignore" << EOF_GITIGNORE
# File log
*.log
logs/
log/

# File cache
cache/
tmp/
temp/
*.cache

# File upload (jika tidak di-backup secara dinamis atau ingin dikecualikan dari Git)
# uploads/
# user_uploads/
# media/

# File konfigurasi lokal yang seharusnya tidak di-commit
config.local.php
*.local.php
.env
*.env
.env.local

# File database (jika disimpan di web root, seharusnya tidak)
*.sql
*.sqlite
*.db

# File sementara editor & OS
*.tmp
*.temp
*.swp
*~
.DS_Store
Thumbs.db

# Direktori vendor (misalnya Composer, Node.js)
vendor/
node_modules/

# File IDE/Editor
.idea/
.vscode/
*.sublime-*
EOF_GITIGNORE
success_msg ".gitignore berhasil dibuat di $WEB_DIR/.gitignore."
echo "Harap tinjau dan sesuaikan $WEB_DIR/.gitignore sesuai kebutuhan proyek Anda."
read -r -p "Tekan Enter untuk melanjutkan..."

info_msg "Menambahkan semua file ke Git dan melakukan commit awal..."
git add .
if git commit -m "Initial commit: Setup web content backup system"; then
    success_msg "Commit awal berhasil dilakukan."
else
    warning_msg "Gagal melakukan commit awal. Mungkin tidak ada file atau perubahan untuk di-commit."
fi

info_msg "Mengkonfigurasi remote 'monitoring' untuk backup..."
if git remote | grep -q "monitoring"; then
    git remote remove monitoring
fi
git remote add monitoring "$MONITOR_USER@$MONITOR_IP:$REMOTE_GIT_BACKUP_PATH" || error_exit "Gagal mengatur remote 'monitoring'."
success_msg "Remote 'monitoring' berhasil dikonfigurasi."

# 8. Pengaturan Grup dan Izin untuk Integrasi Wazuh Active Response
# (Sama seperti sebelumnya, tidak ada perubahan di sini)
# ... (salin Bagian 8 dari skrip asli Anda) ...
# Pastikan WA_AR_BIN_DIR disesuaikan jika perlu, dan path skrip AR juga.
# Pastikan semua chown dan chmod menggunakan variabel yang benar.
# Contoh potongan yang perlu dipastikan:
# cp "/usr/local/bin/containment.py" "${WAZUH_AR_BIN_DIR}/containment.py" && \
# ... dan seterusnya untuk eradication.py dan web_restore.sh
# --- ISI BAGIAN 8 DI SINI ---
read -r -p "Apakah Anda ingin mengatur integrasi Wazuh Active Response (pembuatan grup, izin file)? (Y/n): " SETUP_WAZUH_INTEGRATION
SETUP_WAZUH_INTEGRATION=${SETUP_WAZUH_INTEGRATION:-Y}

if [[ "$SETUP_WAZUH_INTEGRATION" == "y" || "$SETUP_WAZUH_INTEGRATION" == "Y" ]]; then
    info_msg "Memulai pengaturan untuk integrasi Wazuh Active Response..."

    id "$WAZUH_USER" &>/dev/null || error_exit "Pengguna Wazuh '$WAZUH_USER' tidak ditemukan. Instalasi Wazuh AR tidak dapat dilanjutkan."
    getent group "$WAZUH_GROUP" &>/dev/null || error_exit "Grup Wazuh '$WAZUH_GROUP' tidak ditemukan."

    if ! getent group "$SHARED_AR_GROUP" > /dev/null; then
        info_msg "Membuat grup bersama '$SHARED_AR_GROUP'..."
        groupadd "$SHARED_AR_GROUP" || error_exit "Gagal membuat grup '$SHARED_AR_GROUP'."
        success_msg "Grup '$SHARED_AR_GROUP' berhasil dibuat."
    else
        info_msg "Grup bersama '$SHARED_AR_GROUP' sudah ada."
    fi

    if ! groups "$WAZUH_USER" | grep -q "\b$SHARED_AR_GROUP\b"; then
        info_msg "Menambahkan pengguna '$WAZUH_USER' ke grup '$SHARED_AR_GROUP'..."
        usermod -a -G "$SHARED_AR_GROUP" "$WAZUH_USER" || error_exit "Gagal menambahkan '$WAZUH_USER' ke grup '$SHARED_AR_GROUP'."
        success_msg "Pengguna '$WAZUH_USER' berhasil ditambahkan ke grup '$SHARED_AR_GROUP'."
    else
        info_msg "Pengguna '$WAZUH_USER' sudah menjadi anggota grup '$SHARED_AR_GROUP'."
    fi

    info_msg "Mengatur kepemilikan dan izin untuk direktori dan file yang dibutuhkan Wazuh AR..."
    chown -R "root:$SHARED_AR_GROUP" "$WEB_DIR" || warning_msg "Gagal mengatur kepemilikan $WEB_DIR"
    chmod -R g+rwx "$WEB_DIR" || warning_msg "Gagal mengatur izin grup rwx untuk $WEB_DIR"
    find "$WEB_DIR" -type d -exec chmod g+s {} \;

    if [ -d "$WEB_DIR/.git" ]; then
        chown -R "root:$SHARED_AR_GROUP" "$WEB_DIR/.git" || warning_msg "Gagal mengatur kepemilikan $WEB_DIR/.git"
        chmod -R g+rwx "$WEB_DIR/.git" || warning_msg "Gagal mengatur izin grup rwx untuk $WEB_DIR/.git"
    fi
    
    # Izin config.conf akan diatur setelah file final ditulis (setelah SSH key)
    # chown "root:$SHARED_AR_GROUP" "$CONFIG_DIR/config.conf"
    # chmod 640 "$CONFIG_DIR/config.conf"

    WAZUH_AR_LOG_DIR="/var/log/wazuh/active-response" # Pastikan ini konsisten dengan skrip AR
    mkdir -p "$WAZUH_AR_LOG_DIR" || warning_msg "Gagal membuat direktori log Wazuh AR $WAZUH_AR_LOG_DIR."
    if [ -d "$WAZUH_AR_LOG_DIR" ]; then
        chown -R "$WAZUH_USER:$WAZUH_GROUP" "$WAZUH_AR_LOG_DIR" || warning_msg "Gagal mengatur kepemilikan log Wazuh AR."
        chmod -R 750 "$WAZUH_AR_LOG_DIR" || warning_msg "Gagal mengatur izin log Wazuh AR."
    fi
    success_msg "Kepemilikan dan izin untuk Wazuh AR telah diatur (kecuali config.conf yang akan diatur nanti)."

    WAZUH_AR_BIN_DIR="/var/ossec/active-response/bin" 
    if [ ! -d "$WAZUH_AR_BIN_DIR" ]; then
        warning_msg "Direktori Wazuh AR '$WAZUH_AR_BIN_DIR' tidak ditemukan. Lewati penempatan skrip AR."
    else
        info_msg "Menyalin skrip AR (containment.py, eradication.py) ke $WAZUH_AR_BIN_DIR..."
        cp "/usr/local/bin/containment.py" "${WAZUH_AR_BIN_DIR}/containment.py" && \
        chown "root:$WAZUH_GROUP" "${WAZUH_AR_BIN_DIR}/containment.py" && \
        chmod 750 "${WAZUH_AR_BIN_DIR}/containment.py" || warning_msg "Gagal menyalin/mengatur containment.py untuk Wazuh AR."
        
        cp "/usr/local/bin/eradication.py" "${WAZUH_AR_BIN_DIR}/eradication.py" && \
        chown "root:$WAZUH_GROUP" "${WAZUH_AR_BIN_DIR}/eradication.py" && \
        chmod 750 "${WAZUH_AR_BIN_DIR}/eradication.py" || warning_msg "Gagal menyalin/mengatur eradication.py untuk Wazuh AR."

        info_msg "Membuat skrip wrapper web_restore.sh untuk Wazuh AR..."
        cat > "${WAZUH_AR_BIN_DIR}/web_restore.sh" << 'EOF_AR_RESTORE'
#!/bin/bash
# Script Active Response Wazuh untuk menjalankan restore_auto.py

PYTHON_EXEC=$(command -v python3 || command -v python)
RESTORE_SCRIPT="/usr/local/bin/restore_auto.py" 
LOG_DIR="/var/log/wazuh/active-response" # Pastikan sama dengan WAZUH_AR_LOG_DIR di atas
LOG_FILE="$LOG_DIR/restore_ar.log" 

mkdir -p "$LOG_DIR" # chown dan chmod dilakukan oleh install.sh

echo "$(date): Starting web_restore.sh Active Response." >> "$LOG_FILE"
echo "$(date): Alert data: $1 $2 $3 $4 $5 $6 $7 $8" >> "$LOG_FILE" 

if [ ! -f "$RESTORE_SCRIPT" ]; then
    echo "$(date): [ERROR] Skrip restore '$RESTORE_SCRIPT' tidak ditemukan." >> "$LOG_FILE"
    exit 1
fi
if [ -z "$PYTHON_EXEC" ]; then
    echo "$(date): [ERROR] Python3 atau Python tidak ditemukan." >> "$LOG_FILE"
    exit 1
fi

"$PYTHON_EXEC" "$RESTORE_SCRIPT" --auto --alert --non-root >> "$LOG_FILE" 2>&1
STATUS=$?

if [ $STATUS -eq 0 ]; then
    echo "$(date): [SUCCESS] Proses restore otomatis berhasil diselesaikan." >> "$LOG_FILE"
else
    echo "$(date): [ERROR] Proses restore otomatis gagal dengan status $STATUS." >> "$LOG_FILE"
fi
exit $STATUS
EOF_AR_RESTORE
        chown "root:$WAZUH_GROUP" "${WAZUH_AR_BIN_DIR}/web_restore.sh"
        chmod 750 "${WAZUH_AR_BIN_DIR}/web_restore.sh"
        success_msg "Skrip AR berhasil ditempatkan dan wrapper dibuat."

        echo ""
        info_msg "Untuk mengaktifkan Active Response di Wazuh Manager, tambahkan konfigurasi berikut di ossec.conf:"
        echo "----------------------------------------------------------------------------------------------------"
        cat << EOF_WAZUH_CONF
<ossec_config>
  <command>
    <name>web-restore</name>
    <executable>web_restore.sh</executable>
    <expect>alert_data</expect> 
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>web-containment</name>
    <executable>containment.py</executable>
    <expect>alert_data</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>web-eradication</name>
    <executable>eradication.py</executable>
    <expect>alert_data</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <command>web-containment</command>
    <location>local</location>
    <rules_id>$DEFACE_RULE_IDS</rules_id>
    <timeout>300</timeout> 
  </active-response>
  
  <active-response>
    <disabled>no</disabled> 
    <command>web-eradication</command>
    <location>local</location>
    <rules_id>$DEFACE_RULE_IDS</rules_id> 
    <timeout>300</timeout>
  </active-response>
  
  <active-response>
    <command>web-restore</command>
    <location>local</location>
    <rules_id>$DEFACE_RULE_IDS</rules_id> 
    <timeout>300</timeout>
  </active-response>
</ossec_config>
EOF_WAZUH_CONF
        echo "----------------------------------------------------------------------------------------------------"
        echo "CATATAN: Sesuaikan <rules_id> dengan ID aturan yang relevan di sistem Anda."
        read -r -p "Tekan Enter untuk melanjutkan..."
    fi
else
    info_msg "Pengaturan integrasi Wazuh Active Response dilewati."
fi


# 9. Pengaturan Cron Job untuk Backup Otomatis
# --------------------------------------------
info_msg "Pengaturan Backup Otomatis (Cron Job)..."
read -r -p "Apakah Anda ingin mengatur backup otomatis menggunakan cron? (Y/n): " SETUP_CRON
SETUP_CRON=${SETUP_CRON:-Y}

if [[ "$SETUP_CRON" == "y" || "$SETUP_CRON" == "Y" ]]; then
    # Jadwal Cron untuk web-backup-dynamic (misalnya setiap 30 menit)
    read -r -p "Masukkan frekuensi backup file dinamis ke staging (contoh: '*/30 * * * *', default: '*/30 * * * *'): " CRON_DYNAMIC_SCHEDULE
    CRON_DYNAMIC_SCHEDULE=${CRON_DYNAMIC_SCHEDULE:-"*/30 * * * *"}
    CRON_DYNAMIC_LOG_FILE="/var/log/web-backup-dynamic-cron.log"
    CRON_DYNAMIC_COMMAND="$CRON_DYNAMIC_SCHEDULE /usr/local/bin/web-backup-dynamic >> $CRON_DYNAMIC_LOG_FILE 2>&1"

    # Jadwal Cron untuk web-backup (misalnya sekali sehari)
    read -r -p "Masukkan frekuensi backup utama (Git & transfer dinamis) (contoh: '@daily', '0 3 * * *', default: '@daily'): " CRON_MAIN_SCHEDULE
    CRON_MAIN_SCHEDULE=${CRON_MAIN_SCHEDULE:-@daily}
    CRON_MAIN_LOG_FILE="/var/log/web-backup-cron.log"
    CRON_MAIN_COMMAND="$CRON_MAIN_SCHEDULE /usr/local/bin/web-backup >> $CRON_MAIN_LOG_FILE 2>&1"
    
    # Tambahkan cron job (hindari duplikasi)
    CRONTAB_CONTENT=$(crontab -l 2>/dev/null)
    NEW_CRONTAB_CONTENT="$CRONTAB_CONTENT"

    if echo "$CRONTAB_CONTENT" | grep -qF "/usr/local/bin/web-backup-dynamic"; then
        info_msg "Cron job untuk web-backup-dynamic sepertinya sudah ada."
    else
        NEW_CRONTAB_CONTENT="${NEW_CRONTAB_CONTENT}
$CRON_DYNAMIC_COMMAND"
        success_msg "Cron job untuk web-backup-dynamic akan ditambahkan: $CRON_DYNAMIC_COMMAND"
    fi

    if echo "$CRONTAB_CONTENT" | grep -qF "/usr/local/bin/web-backup"; then
        info_msg "Cron job untuk web-backup utama sepertinya sudah ada."
    else
        NEW_CRONTAB_CONTENT="${NEW_CRONTAB_CONTENT}
$CRON_MAIN_COMMAND"
        success_msg "Cron job untuk web-backup utama akan ditambahkan: $CRON_MAIN_COMMAND"
    fi
    
    # Hanya tulis ke crontab jika ada perubahan
    if [ "$NEW_CRONTAB_CONTENT" != "$CRONTAB_CONTENT" ]; then
        echo "$NEW_CRONTAB_CONTENT" | sed '/^$/d' | crontab - || error_exit "Gagal menambahkan cron job." # sed '/^$/d' untuk hapus baris kosong
        info_msg "Log cron job akan disimpan di $CRON_DYNAMIC_LOG_FILE dan $CRON_MAIN_LOG_FILE"
    fi
else
    info_msg "Pengaturan cron job untuk backup otomatis dilewati."
fi

# 10. Konfigurasi Kunci SSH untuk Koneksi ke Server Monitoring
# ------------------------------------------------------------
info_msg "Konfigurasi Kunci SSH untuk koneksi ke server monitoring ($MONITOR_USER@$MONITOR_IP)..."
SSH_DIR_ROOT="/root/.ssh" 
mkdir -p "$SSH_DIR_ROOT"
chmod 700 "$SSH_DIR_ROOT"

SSH_KEY_FILE="$SSH_DIR_ROOT/id_rsa_web_backup" 

if [ ! -f "$SSH_KEY_FILE" ]; then
    info_msg "Membuat kunci SSH baru di $SSH_KEY_FILE..."
    ssh-keygen -t rsa -b 4096 -f "$SSH_KEY_FILE" -N "" -C "web_backup_$(hostname -s 2>/dev/null || hostname)" || error_exit "Gagal membuat kunci SSH."
    success_msg "Kunci SSH berhasil dibuat."
else
    info_msg "Kunci SSH $SSH_KEY_FILE sudah ada."
fi
SSH_IDENTITY_FILE_PATH="$SSH_KEY_FILE" # Simpan path kunci untuk config.conf
info_msg "Kunci publik Anda adalah:"
cat "${SSH_KEY_FILE}.pub"
echo ""

# --- MENULIS FILE KONFIGURASI config.conf SEKARANG ---
info_msg "Menulis/Memperbarui file konfigurasi $CONFIG_DIR/config.conf dengan semua nilai..."
cat > "$CONFIG_DIR/config.conf" << EOF
# Konfigurasi Umum
WEB_DIR="$WEB_DIR"
PASSWORD="$ENCODED_PASSWORD"
WEB_SERVER_USER="$WEB_SERVER_USER"
WEB_SERVER_GROUP="$WEB_SERVER_GROUP"

# Konfigurasi Server Monitoring (untuk Backup)
MONITOR_IP="$MONITOR_IP"
MONITOR_USER="$MONITOR_USER"
REMOTE_GIT_BACKUP_PATH="$REMOTE_GIT_BACKUP_PATH"
SSH_IDENTITY_FILE="$SSH_IDENTITY_FILE_PATH"

# Konfigurasi Backup File Dinamis
BACKUP_DYNAMIC="$BACKUP_DYNAMIC"
LOCAL_DYNAMIC_STAGING_DIR="$LOCAL_DYNAMIC_STAGING_DIR"
REMOTE_DYNAMIC_BACKUP_PATH="$REMOTE_DYNAMIC_BACKUP_PATH"
LOCAL_DYNAMIC_RESTORE_CACHE_DIR="$LOCAL_DYNAMIC_RESTORE_CACHE_DIR"
DYNAMIC_DIRS=(
    "logs" "cache" "tmp" "temp" "uploads" "media" "sessions" "wp-content/uploads" "wp-content/cache"
) # Sesuaikan DYNAMIC_DIRS dengan kebutuhan Anda

# Konfigurasi Eradication
QUARANTINE_DIR="$QUARANTINE_DIR"
YARA_RULES_DIR="$YARA_RULES_DIR"
CLAMD_SOCKET="$CLAMD_SOCKET"
ERADICATION_SUSPICIOUS_PATTERNS="$DEFAULT_ERADICATION_PATTERNS"

# Konfigurasi Containment
DEFACE_RULE_IDS="$DEFACE_RULE_IDS"
ATTACK_RULE_IDS="$ATTACK_RULE_IDS"

# Konfigurasi Pengguna & Grup Wazuh
WAZUH_USER="$WAZUH_USER"
WAZUH_GROUP="$WAZUH_GROUP"
SHARED_AR_GROUP="$SHARED_AR_GROUP"

# Konfigurasi Integrasi YETI (CTI)
YETI_ENABLED="$YETI_ENABLED"
YETI_API_URL="$YETI_API_URL"
YETI_API_KEY="$YETI_API_KEY"
EOF

# Atur izin file konfigurasi
# Jika Wazuh AR diaktifkan, grup SHARED_AR_GROUP perlu bisa baca
if [[ "$SETUP_WAZUH_INTEGRATION" == "y" || "$SETUP_WAZUH_INTEGRATION" == "Y" ]]; then
    chown "root:$SHARED_AR_GROUP" "$CONFIG_DIR/config.conf" || warning_msg "Gagal chown $CONFIG_DIR/config.conf"
    chmod 640 "$CONFIG_DIR/config.conf" || warning_msg "Gagal chmod 640 $CONFIG_DIR/config.conf"
else
    chown root:root "$CONFIG_DIR/config.conf" || warning_msg "Gagal chown $CONFIG_DIR/config.conf"
    chmod 600 "$CONFIG_DIR/config.conf" || warning_msg "Gagal chmod 600 $CONFIG_DIR/config.conf"
fi
success_msg "File konfigurasi $CONFIG_DIR/config.conf berhasil dibuat/diperbarui."
# --- AKHIR PENULISAN config.conf ---

read -r -p "Apakah Anda ingin mencoba menyalin kunci SSH ke server monitoring sekarang (ssh-copy-id)? (Y/n): " COPY_SSH_KEY
COPY_SSH_KEY=${COPY_SSH_KEY:-Y}

if [[ "$COPY_SSH_KEY" == "y" || "$COPY_SSH_KEY" == "Y" ]]; then
    info_msg "Mencoba menyalin kunci SSH ke $MONITOR_USER@$MONITOR_IP..."
    info_msg "Anda mungkin akan diminta password untuk $MONITOR_USER@$MONITOR_IP."
    
    # Pastikan known_hosts diupdate
    mkdir -p "$SSH_DIR_ROOT" 
    ssh-keyscan -H "$MONITOR_IP" >> "$SSH_DIR_ROOT/known_hosts" 2>/dev/null
    sort -u "$SSH_DIR_ROOT/known_hosts" -o "$SSH_DIR_ROOT/known_hosts"
    
    if ssh-copy-id -i "$SSH_IDENTITY_FILE_PATH.pub" "$MONITOR_USER@$MONITOR_IP"; then
        success_msg "Kunci SSH berhasil disalin ke server monitoring."
        info_msg "PENTING: Pastikan Server Monitoring dikonfigurasi untuk menerima koneksi menggunakan kunci ini."
        info_msg "Anda mungkin perlu menambahkan 'IdentityFile $SSH_IDENTITY_FILE_PATH' ke konfigurasi SSH client (/etc/ssh/ssh_config atau $SSH_DIR_ROOT/config) jika cron atau skrip lain tidak menggunakan kunci yang benar secara otomatis."
        echo "Host $MONITOR_IP" >> "$SSH_DIR_ROOT/config"
        echo "  IdentityFile $SSH_IDENTITY_FILE_PATH" >> "$SSH_DIR_ROOT/config"
        chmod 600 "$SSH_DIR_ROOT/config"
        info_msg "Entri Host dan IdentityFile ditambahkan ke $SSH_DIR_ROOT/config untuk pengguna root."

    else
        warning_msg "Gagal menyalin kunci SSH secara otomatis."
        echo "Mohon salin kunci publik di atas secara manual ke file ~/.ssh/authorized_keys di server monitoring untuk pengguna $MONITOR_USER."
        echo "Path kunci publik di server ini: ${SSH_IDENTITY_FILE_PATH}.pub"
    fi
else
    info_msg "Penyalinan kunci SSH dilewati. Pastikan Anda mengkonfigurasinya secara manual agar backup otomatis berfungsi."
    info_msg "Anda mungkin perlu menambahkan 'IdentityFile $SSH_IDENTITY_FILE_PATH' ke konfigurasi SSH client (/etc/ssh/ssh_config atau $SSH_DIR_ROOT/config)."
fi


# 11. Membuat Direktori untuk File Dinamis (jika dikonfigurasi)
# --------------------------------------------------------------
# Pastikan config.conf sudah termuat untuk DYNAMIC_DIRS
if [ -f "$CONFIG_DIR/config.conf" ]; then
    # shellcheck source=/dev/null
    source "$CONFIG_DIR/config.conf"
else
    error_exit "File konfigurasi '$CONFIG_DIR/config.conf' tidak ditemukan sebelum setup direktori dinamis."
fi

if [[ "$BACKUP_DYNAMIC" == "true" ]]; then
    info_msg "Memastikan direktori untuk file dinamis (sesuai DYNAMIC_DIRS) ada di $WEB_DIR..."
    if declare -p DYNAMIC_DIRS &>/dev/null && [[ "$(declare -p DYNAMIC_DIRS)" =~ "declare -a" ]]; then # Cek jika DYNAMIC_DIRS adalah array
        for dir_rel_path in "${DYNAMIC_DIRS[@]}"; do
            abs_dir_path="$WEB_DIR/$dir_rel_path"
            if [ ! -d "$abs_dir_path" ]; then
                info_msg "Membuat direktori dinamis: $abs_dir_path"
                mkdir -p "$abs_dir_path" || warning_msg "Gagal membuat $abs_dir_path"
                if [ -d "$abs_dir_path" ]; then 
                    chown "$WEB_SERVER_USER:$WEB_SERVER_GROUP" "$abs_dir_path" || warning_msg "Gagal chown $abs_dir_path"
                    chmod 775 "$abs_dir_path" || warning_msg "Gagal chmod $abs_dir_path" 
                fi
            else
                info_msg "Direktori dinamis $abs_dir_path sudah ada."
            fi
        done
        success_msg "Pengecekan direktori dinamis selesai."
    else
        warning_msg "Variabel DYNAMIC_DIRS tidak terdefinisi sebagai array di config.conf atau config.conf belum termuat dengan benar. Tidak dapat membuat direktori dinamis."
    fi
fi

# 12. Mencoba Backup Awal
# -----------------------
info_msg "Melakukan backup awal untuk pengujian..."
echo "CATATAN: Jika ini adalah setup pertama kali di server monitoring, backup awal mungkin gagal jika"
echo "         repository bare belum diinisialisasi dengan benar di sana atau SSH belum sepenuhnya siap."
echo "         Anda mungkin perlu menjalankan 'monitoring_setup.sh' di server monitoring terlebih dahulu."
read -r -p "Lanjutkan dengan backup awal? (Y/n): " ATTEMPT_INITIAL_BACKUP
ATTEMPT_INITIAL_BACKUP=${ATTEMPT_INITIAL_BACKUP:-Y}
if [[ "$ATTEMPT_INITIAL_BACKUP" == "y" || "$ATTEMPT_INITIAL_BACKUP" == "Y" ]]; then
    # Jalankan backup dinamis ke staging dulu
    info_msg "Menjalankan web-backup-dynamic untuk membuat arsip dinamis awal..."
    if /usr/local/bin/web-backup-dynamic; then
        success_msg "Backup dinamis ke staging berhasil."
    else
        warning_msg "Backup dinamis ke staging gagal. Lanjutkan dengan backup utama."
    fi
    
    info_msg "Menjalankan backup utama (Git dan transfer dinamis)..."
    if /usr/local/bin/web-backup; then # Skrip web-backup yang sudah dimodifikasi
        success_msg "Backup awal berhasil diselesaikan."
    else
        warning_msg "Backup awal gagal. Silakan periksa log dan konfigurasi (SSH, path remote, dll)."
        warning_msg "Anda dapat mencoba backup manual dengan perintah: sudo /usr/local/bin/web-backup"
    fi
else
    info_msg "Backup awal dilewati."
fi


# 13. Pesan Akhir dan Informasi
# -----------------------------
# (Sama seperti sebelumnya, pastikan variabel yang ditampilkan sudah benar)
# ... (salin Bagian 13 dari skrip asli Anda) ...
echo ""
echo "================================================================="
echo "      INSTALASI SISTEM KEAMANAN WEB SERVER SELESAI               "
echo "================================================================="
echo ""
echo "Ringkasan Konfigurasi:"
echo "----------------------"
echo "Direktori Web Utama: $WEB_DIR"
echo "File Konfigurasi Utama: $CONFIG_DIR/config.conf"
echo "Server Monitoring IP: $MONITOR_IP (User: $MONITOR_USER)"
echo "Path Backup Git Remote: $REMOTE_GIT_BACKUP_PATH"
echo "Kunci SSH Identity File: $SSH_IDENTITY_FILE_PATH"
if [[ "$BACKUP_DYNAMIC" == "true" ]]; then
    echo "Backup File Dinamis: Aktif"
    echo "  - Staging Lokal (Backup): $LOCAL_DYNAMIC_STAGING_DIR"
    echo "  - Cache Lokal (Restore): $LOCAL_DYNAMIC_RESTORE_CACHE_DIR"
    echo "  - Path Remote Dinamis: $REMOTE_DYNAMIC_BACKUP_PATH"
fi
echo "Direktori Karantina: $QUARANTINE_DIR"
if [[ "$YETI_ENABLED" == "true" ]]; then
    echo "Integrasi YETI: Aktif (URL: $YETI_API_URL)"
fi
echo ""
echo "Skrip Utama:"
echo "  Backup Dinamis ke Staging: sudo /usr/local/bin/web-backup-dynamic"
echo "  Backup Utama (Git & Transfer Dinamis): sudo /usr/local/bin/web-backup"
echo "  Restore Manual (Interaktif): sudo /usr/local/bin/web-restore" # Jika web-restore.py masih ada dan digunakan
echo "  Restore Otomatis (via Wazuh): /usr/local/bin/restore_auto.py"
echo "  Containment (via Wazuh): /usr/local/bin/containment.py (atau di $WAZUH_AR_BIN_DIR)"
echo "  Eradication (via Wazuh): /usr/local/bin/eradication.py (atau di $WAZUH_AR_BIN_DIR)"
echo ""
echo "PENTING:"
echo "- Pastikan server monitoring Anda sudah di-setup untuk menerima backup (menggunakan skrip 'monitoring_setup.sh' atau setara)."
echo "- Periksa konfigurasi SSH antara server ini dan server monitoring, terutama jika backup otomatis gagal."
echo "- Jika menggunakan integrasi Wazuh, konfigurasikan Wazuh Manager (ossec.conf) seperti instruksi yang ditampilkan."
echo "- Tinjau file $CONFIG_DIR/config.conf untuk semua pengaturan."
echo "- Sesuaikan file $WEB_DIR/.gitignore dengan kebutuhan proyek Anda."
echo "- Jika Anda mengubah nama pengguna/grup web server atau Wazuh, pastikan semua izin file dan direktori sesuai."
echo "- URL Repository untuk mengunduh skrip: $REPO_URL_BASE. Pastikan skrip-skrip di sana adalah versi terbaru yang sudah diperbaiki."
echo ""
echo "Terima kasih telah menggunakan sistem ini."
echo "================================================================="

# Membersihkan direktori temporer
cd /
rm -rf "$TEMP_DIR"
info_msg "Direktori temporer $TEMP_DIR telah dihapus."
