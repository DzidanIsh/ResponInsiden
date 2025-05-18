#!/bin/bash

# Script Instalasi untuk Sistem Backup dan Restore Web Server
# ------------------------------------------------------

# Fungsi untuk menampilkan pesan error dan keluar
function error_exit {
    echo -e "\e[31m[ERROR] $1\e[0m"
    exit 1
}

# Fungsi untuk menampilkan pesan sukses
function success_msg {
    echo -e "\e[32m[SUCCESS] $1\e[0m"
}

# Fungsi untuk menampilkan pesan info
function info_msg {
    echo -e "\e[34m[INFO] $1\e[0m"
}

# Banner
echo "================================================================="
echo "      INSTALASI SISTEM BACKUP DAN RESTORE ANTI-DEFACEMENT        "
echo "================================================================="
echo ""

# Verifikasi bahwa script dijalankan sebagai root
if [ "$(id -u)" -ne 0 ]; then
    error_exit "Script ini harus dijalankan sebagai root."
fi

# Periksa apakah git dan python3 terinstall
command -v git >/dev/null 2>&1 || error_exit "Git tidak ditemukan. Silakan install dengan: apt-get install git"
command -v python3 >/dev/null 2>&1 || error_exit "Python3 tidak ditemukan. Silakan install dengan: apt-get install python3"

# Konfigurasi identitas Git jika belum dikonfigurasi
info_msg "Mengkonfigurasi identitas Git..."

# Tentukan nama pengguna untuk web server
read -p "Masukkan nama pengguna untuk web server (default: webserver): " WEB_USERNAME
WEB_USERNAME=${WEB_USERNAME:-webserver}

# Cek apakah user.email sudah dikonfigurasi global
if ! git config --global user.email >/dev/null 2>&1; then
    git config --global user.email "backup@$WEB_USERNAME.local"
    info_msg "Git user.email dikonfigurasi ke backup@$WEB_USERNAME.local"
fi
# Cek apakah user.name sudah dikonfigurasi global
if ! git config --global user.name >/dev/null 2>&1; then
    git config --global user.name "$WEB_USERNAME Backup System"
    info_msg "Git user.name dikonfigurasi ke $WEB_USERNAME Backup System"
fi

# Periksa apakah pip3 terinstall
command -v pip3 >/dev/null 2>&1 || {
    info_msg "Pip3 tidak ditemukan. Menginstall pip3..."
    apt-get update
    apt-get install -y python3-pip || error_exit "Gagal menginstall pip3"
}

# Install dependensi Python yang diperlukan untuk restore.py
info_msg "Menginstall dependensi Python..."
pip3 install paramiko gitpython requests || error_exit "Gagal menginstall dependensi Python"

# Tentukan direktori untuk backup
echo "Menentukan direktori yang akan di-backup..."
read -p "Masukkan path direktori web server (default: /var/www/html): " WEB_DIR
WEB_DIR=${WEB_DIR:-/var/www/html}

# Verifikasi direktori web server
if [ ! -d "$WEB_DIR" ]; then
    error_exit "Direktori $WEB_DIR tidak ditemukan!"
fi

# Meminta detail server monitoring
echo ""
echo "Konfigurasi Server Monitoring"
echo "----------------------------"
read -p "Masukkan IP Server Monitoring (default: 192.168.92.10): " MONITOR_IP
MONITOR_IP=${MONITOR_IP:-192.168.92.10}
read -p "Masukkan Username SSH Server Monitoring (default: wazuh): " MONITOR_USER
MONITOR_USER=${MONITOR_USER:-wazuh}
read -p "Masukkan Path Direktori Backup di Server Monitoring (default: /var/backup/web): " BACKUP_DIR
BACKUP_DIR=${BACKUP_DIR:-/var/backup/web}

# Membuat dan mengatur password
echo ""
echo "Pengaturan Password Backup dan Restore"
echo "-------------------------------------"
read -sp "Masukkan password untuk backup dan restore: " BACKUP_PASSWORD
echo ""
read -sp "Konfirmasi password: " CONFIRM_PASSWORD
echo ""

if [ "$BACKUP_PASSWORD" != "$CONFIRM_PASSWORD" ]; then
    error_exit "Password tidak cocok!"
fi

# Enkripsi password (Menggunakan base64 sebagai enkripsi sederhana - untuk sistem produksi gunakan enkripsi yang lebih kuat)
ENCODED_PASSWORD=$(echo -n "$BACKUP_PASSWORD" | base64)

# Membuat direktori konfigurasi
CONFIG_DIR="/etc/web-backup"
mkdir -p "$CONFIG_DIR" || error_exit "Gagal membuat direktori konfigurasi $CONFIG_DIR"

# Menyimpan konfigurasi
cat > "$CONFIG_DIR/config.conf" << EOF
WEB_DIR="$WEB_DIR"
MONITOR_IP="$MONITOR_IP"
MONITOR_USER="$MONITOR_USER"
BACKUP_DIR="$BACKUP_DIR"
PASSWORD="$ENCODED_PASSWORD"
EOF

# Atur permission yang aman
chmod 600 "$CONFIG_DIR/config.conf"

# Inisialisasi repository Git di direktori web
echo ""
info_msg "Mengatur repository Git untuk direktori web..."
cd "$WEB_DIR" || error_exit "Gagal masuk ke direktori $WEB_DIR"

# Hapus repository Git sebelumnya jika ada
if [ -d ".git" ]; then
    info_msg "Menghapus repository Git sebelumnya..."
    rm -rf .git
fi

# Inisialisasi repository Git baru
git init || error_exit "Gagal menginisialisasi repository Git"

# Konfigurasi Git lokal untuk repository ini
git config --local user.email "backup@$WEB_USERNAME.local"
git config --local user.name "$WEB_USERNAME Backup System"

# Tambahkan .gitignore default
echo "*.log" > .gitignore
echo "tmp/" >> .gitignore

# Commit awal
info_msg "Melakukan commit awal..."
git add .

git commit -m "Initial backup of web server content" || {
    if [ $? -eq 1 ]; then
        info_msg "Tidak ada perubahan yang perlu di-commit."
    else
        error_exit "Gagal melakukan commit."
    fi
}

# Konfigurasi remote repository untuk backup
info_msg "Mengkonfigurasi remote repository..."
# Hapus remote sebelumnya jika ada
git remote remove monitoring 2>/dev/null
# Tambahkan remote baru dengan format yang benar
git remote add monitoring "$MONITOR_USER@$MONITOR_IP:$BACKUP_DIR" || 
    error_exit "Gagal mengatur remote repository."

# Menyalin script backup dan restore ke lokasi yang tepat
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
cp "$SCRIPT_DIR/backup.sh" /usr/local/bin/web-backup || error_exit "Gagal menyalin script backup"
cp "$SCRIPT_DIR/restore.py" /usr/local/bin/web-restore || error_exit "Gagal menyalin script restore"

# Salin script restore_auto.py jika ada
if [ -f "$SCRIPT_DIR/restore_auto.py" ]; then
    cp "$SCRIPT_DIR/restore_auto.py" /usr/local/bin/restore_auto.py || error_exit "Gagal menyalin script restore_auto.py"
    chmod +x /usr/local/bin/restore_auto.py
    info_msg "Script restore_auto.py berhasil disalin ke /usr/local/bin/"
else
    info_msg "Script restore_auto.py tidak ditemukan di direktori saat ini."
fi

# Atur permission eksekusi
chmod +x /usr/local/bin/web-backup
chmod +x /usr/local/bin/web-restore

# Konfirmasi apakah pengguna ingin mengatur cron job untuk backup otomatis
echo ""
echo "Pengaturan Backup Otomatis"
echo "-------------------------"
read -p "Apakah Anda ingin mengatur backup otomatis? (y/n, default: y): " SETUP_CRON
SETUP_CRON=${SETUP_CRON:-y}

if [ "$SETUP_CRON" = "y" ] || [ "$SETUP_CRON" = "Y" ]; then
    read -p "Masukkan frekuensi backup (contoh: @daily, @hourly, atau crontab seperti '0 3 * * *', default: @daily): " CRON_SCHEDULE
    CRON_SCHEDULE=${CRON_SCHEDULE:-@daily}
    
    # Tambahkan cron job
    (crontab -l 2>/dev/null; echo "$CRON_SCHEDULE /usr/local/bin/web-backup > /var/log/web-backup.log 2>&1") | crontab -
    info_msg "Backup otomatis telah diatur untuk dijalankan: $CRON_SCHEDULE"
fi

# Konfigurasi SSH untuk remote repository
echo ""
echo "Konfigurasi SSH untuk Koneksi ke Server Monitoring"
echo "-------------------------------------------------"
info_msg "Mengkonfigurasi SSH untuk koneksi ke server monitoring..."

# Periksa apakah kunci SSH sudah ada
if [ ! -f ~/.ssh/id_rsa ]; then
    info_msg "Membuat kunci SSH baru..."
    ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N "" -C "backup@$WEB_USERNAME" || 
        error_exit "Gagal membuat kunci SSH"
else
    info_msg "Kunci SSH sudah ada di ~/.ssh/id_rsa"
fi

# Tanya apakah ingin menyalin kunci SSH ke server monitoring
read -p "Apakah Anda ingin menyalin kunci SSH ke server monitoring? (y/n, default: y): " COPY_SSH_KEY
COPY_SSH_KEY=${COPY_SSH_KEY:-y}

if [ "$COPY_SSH_KEY" = "y" ] || [ "$COPY_SSH_KEY" = "Y" ]; then
    info_msg "Mencoba menyalin kunci SSH ke server monitoring ($MONITOR_IP)..."
    # Tambahkan server ke known_hosts tanpa prompting
    ssh-keyscan -H "$MONITOR_IP" >> ~/.ssh/known_hosts 2>/dev/null
    
    # Coba ssh-copy-id
    if ! ssh-copy-id "$MONITOR_USER@$MONITOR_IP"; then
        echo "Gagal menyalin kunci SSH secara otomatis."
        echo "Mohon salin kunci SSH secara manual dengan perintah:"
        echo "ssh-copy-id $MONITOR_USER@$MONITOR_IP"
        echo ""
        echo "Atau salin output berikut ke file authorized_keys di server monitoring:"
        cat ~/.ssh/id_rsa.pub
        echo ""
        read -p "Tekan Enter untuk melanjutkan setelah mengkonfigurasi SSH..."
    else
        success_msg "Kunci SSH berhasil disalin ke server monitoring"
    fi
fi

# Mencoba backup pertama
echo ""
info_msg "Melakukan backup awal untuk pengujian..."
/usr/local/bin/web-backup || {
    echo "Peringatan: Backup awal gagal, tapi instalasi tetap dilanjutkan."
    echo "Pastikan konfigurasi SSH telah benar dan server monitoring siap menerima backup."
    echo "Anda dapat mencoba backup manual dengan perintah: sudo web-backup"
}

# Pengaturan izin untuk menjalankan restore tanpa root - integrasi Wazuh
echo ""
echo "Konfigurasi Izin untuk Restore Otomatis (Wazuh)"
echo "---------------------------------------------"
read -p "Apakah Anda ingin mengkonfigurasi restore otomatis dengan Wazuh (tanpa root)? (y/n, default: y): " SETUP_WAZUH
SETUP_WAZUH=${SETUP_WAZUH:-y}

if [ "$SETUP_WAZUH" = "y" ] || [ "$SETUP_WAZUH" = "Y" ]; then
    # Periksa apakah Wazuh diinstal
    if [ -d "/var/ossec" ]; then
        # Buat grup web-restore
        if ! getent group web-restore > /dev/null; then
            info_msg "Membuat grup web-restore..."
            groupadd web-restore || error_exit "Gagal membuat grup web-restore"
        else
            info_msg "Grup web-restore sudah ada"
        fi
        
        # Tambahkan user wazuh ke grup
        if id -nG wazuh | grep -qw "web-restore"; then
            info_msg "User wazuh sudah ada dalam grup web-restore"
        else
            info_msg "Menambahkan user wazuh ke grup web-restore..."
            usermod -a -G web-restore wazuh || error_exit "Gagal menambahkan user wazuh ke grup web-restore"
        fi
        
        # Set izin direktori web
        info_msg "Mengatur izin grup untuk direktori web..."
        chown -R :web-restore "$WEB_DIR" || error_exit "Gagal mengatur kepemilikan grup untuk $WEB_DIR"
        chmod -R g+rw "$WEB_DIR" || error_exit "Gagal mengatur izin grup untuk $WEB_DIR"
        
        # Set izin repo git
        if [ -d "$WEB_DIR/.git" ]; then
            info_msg "Mengatur izin grup untuk repository Git..."
            chown -R :web-restore "$WEB_DIR/.git" || error_exit "Gagal mengatur kepemilikan grup untuk .git"
            chmod -R g+rw "$WEB_DIR/.git" || error_exit "Gagal mengatur izin grup untuk .git"
        fi
        
        # Set izin file konfigurasi
        info_msg "Mengatur izin file konfigurasi..."
        chown root:web-restore "$CONFIG_DIR/config.conf" || error_exit "Gagal mengatur kepemilikan config.conf"
        chmod 640 "$CONFIG_DIR/config.conf" || error_exit "Gagal mengatur izin untuk config.conf"
        
        # Buat dan atur izin direktori log
        info_msg "Membuat direktori log..."
        mkdir -p "/var/log/wazuh/active-response" || error_exit "Gagal membuat direktori log"
        chown -R wazuh:wazuh "/var/log/wazuh/active-response" || error_exit "Gagal mengatur kepemilikan direktori log"
        chmod 750 "/var/log/wazuh/active-response" || error_exit "Gagal mengatur izin direktori log"
        
        # Salin script ke direktori active-response wazuh
        if [ -f "/usr/local/bin/restore_auto.py" ]; then
            info_msg "Menyalin script restore_auto.py ke direktori active-response Wazuh..."
            
            # Buat script wrapper untuk active-response
            cat > "/var/ossec/active-response/bin/web_restore.sh" << 'EOF'
#!/bin/bash

# Script active-response untuk menjalankan restore otomatis

LOG_FILE="/var/log/wazuh/active-response/restore.log"
RESTORE_SCRIPT="/usr/local/bin/restore_auto.py"

# Fungsi logging
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
    echo "$1"
}

# Log awal eksekusi
log "[INFO] Memulai proses restore otomatis"

# Jalankan restore_auto.py dalam mode otomatis dengan alert dan non-root
python3 "$RESTORE_SCRIPT" --auto --alert --non-root 2>> "$LOG_FILE"

# Periksa status eksekusi
if [ $? -eq 0 ]; then
    log "[SUCCESS] Proses restore otomatis berhasil diselesaikan"
    exit 0
else
    log "[ERROR] Proses restore otomatis gagal"
    exit 1
fi
EOF
            
            # Set izin skrip
            chmod +x "/var/ossec/active-response/bin/web_restore.sh"
            chown root:wazuh "/var/ossec/active-response/bin/web_restore.sh"
            
            success_msg "Script active-response berhasil dikonfigurasi."
            
            # Instruksi konfigurasi Wazuh
            echo ""
            echo "Untuk mengkonfigurasi Wazuh Manager, tambahkan konfigurasi berikut di ossec.conf:"
            echo "------------------------------------------------------------"
            echo "<command>"
            echo "  <name>web-restore</name>"
            echo "  <executable>web_restore.sh</executable>"
            echo "  <expect></expect>"
            echo "  <timeout_allowed>yes</timeout_allowed>"
            echo "</command>"
            echo ""
            echo "<active-response>"
            echo "  <command>web-restore</command>"
            echo "  <location>local</location>"
            echo "  <rules_id>100501,100502,100503</rules_id>"
            echo "  <timeout>60</timeout>"
            echo "</active-response>"
            echo "------------------------------------------------------------"
        else
            warning "Script restore_auto.py tidak ditemukan di /usr/local/bin/. Konfigurasi active-response tidak dilakukan."
        fi
    else
        warning "Wazuh tidak terdeteksi. Lewati konfigurasi izin Wazuh."
    fi
fi

echo ""
echo "Konfigurasi File Dinamis"
echo "----------------------"
echo "File dinamis adalah file yang sering berubah seperti log, cache, upload, dll."
echo "File-file ini sebaiknya tidak di-backup atau di-restore untuk menghindari konflik."
echo ""

# Buat file .gitignore dengan pengecualian default
cat > "$WEB_DIR/.gitignore" << 'EOF'
# File log
*.log
logs/
log/

# File cache
cache/
tmp/
temp/
*.cache

# File upload
uploads/
user_uploads/
media/

# File konfigurasi lokal
config.local.php
.env.local
*.local

# File database
*.sql
*.sqlite
*.db

# File sementara
*.tmp
*.temp
*.swp
*~

# File backup
*.bak
*.backup
*_backup

# File IDE
.idea/
.vscode/
*.sublime-*

# File sistem
.DS_Store
Thumbs.db
EOF

# Tanya apakah ingin menambahkan pengecualian kustom
read -p "Apakah Anda ingin menambahkan pengecualian kustom untuk file dinamis? (y/n, default: y): " ADD_CUSTOM_EXCLUDE
ADD_CUSTOM_EXCLUDE=${ADD_CUSTOM_EXCLUDE:-y}

if [ "$ADD_CUSTOM_EXCLUDE" = "y" ] || [ "$ADD_CUSTOM_EXCLUDE" = "Y" ]; then
    echo ""
    echo "Masukkan path file atau direktori yang ingin dikecualikan (satu per baris)"
    echo "Contoh:"
    echo "  - wp-content/uploads/    (untuk WordPress)"
    echo "  - storage/app/public/    (untuk Laravel)"
    echo "  - var/cache/            (untuk Symfony)"
    echo "  - data/                 (untuk aplikasi umum)"
    echo ""
    echo "Ketik 'selesai' untuk mengakhiri"
    
    while true; do
        read -p "Masukkan path yang ingin dikecualikan: " EXCLUDE_PATH
        if [ "$EXCLUDE_PATH" = "selesai" ]; then
            break
        fi
        
        # Validasi path
        if [ -n "$EXCLUDE_PATH" ]; then
            # Tambahkan ke .gitignore
            echo "$EXCLUDE_PATH" >> "$WEB_DIR/.gitignore"
            info_msg "Path $EXCLUDE_PATH ditambahkan ke pengecualian"
        fi
    done
fi

# Buat direktori untuk file dinamis jika belum ada
DYNAMIC_DIRS=(
    "logs"
    "cache"
    "tmp"
    "uploads"
    "media"
)

for dir in "${DYNAMIC_DIRS[@]}"; do
    if [ ! -d "$WEB_DIR/$dir" ]; then
        mkdir -p "$WEB_DIR/$dir"
        chmod 775 "$WEB_DIR/$dir"
        info_msg "Direktori $dir dibuat di $WEB_DIR"
    fi
done

# Tambahkan konfigurasi file dinamis ke config.conf
cat >> "$CONFIG_DIR/config.conf" << EOF

# Konfigurasi file dinamis
DYNAMIC_DIRS=(
    "logs"
    "cache"
    "tmp"
    "uploads"
    "media"
)

# Backup terpisah untuk file dinamis
BACKUP_DYNAMIC=true
DYNAMIC_BACKUP_DIR="$BACKUP_DIR/dynamic"
EOF

# Buat script untuk backup file dinamis
cat > "/usr/local/bin/web-backup-dynamic" << 'EOF'
#!/bin/bash

# Script untuk backup file dinamis
CONFIG_FILE="/etc/web-backup/config.conf"

# Load konfigurasi
source "$CONFIG_FILE"

# Fungsi untuk menampilkan pesan
function log_msg {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Buat direktori backup jika belum ada
mkdir -p "$DYNAMIC_BACKUP_DIR"

# Backup setiap direktori dinamis
for dir in "${DYNAMIC_DIRS[@]}"; do
    if [ -d "$WEB_DIR/$dir" ]; then
        timestamp=$(date +%Y%m%d_%H%M%S)
        backup_name="${dir}_${timestamp}.tar.gz"
        
        # Buat backup
        tar -czf "$DYNAMIC_BACKUP_DIR/$backup_name" -C "$WEB_DIR" "$dir"
        
        if [ $? -eq 0 ]; then
            log_msg "Backup $dir berhasil: $backup_name"
        else
            log_msg "Gagal backup $dir"
        fi
    fi
done

# Hapus backup yang lebih tua dari 7 hari
find "$DYNAMIC_BACKUP_DIR" -type f -mtime +7 -delete
EOF

chmod +x "/usr/local/bin/web-backup-dynamic"

# Modifikasi script backup utama untuk memanggil backup dinamis
sed -i '/^# Backup ke remote repository/a \
# Backup file dinamis jika diaktifkan\
if [ "$BACKUP_DYNAMIC" = true ]; then\
    /usr/local/bin/web-backup-dynamic\
fi' /usr/local/bin/web-backup

echo ""
echo "================================================================="
echo "      INSTALASI BERHASIL DISELESAIKAN                           "
echo "================================================================="
echo ""
echo "Script backup tersedia di: /usr/local/bin/web-backup"
echo "Script restore tersedia di: /usr/local/bin/web-restore"
if [ -f "/usr/local/bin/restore_auto.py" ]; then
    echo "Script restore otomatis tersedia di: /usr/local/bin/restore_auto.py"
fi
echo "Konfigurasi disimpan di: $CONFIG_DIR/config.conf"
echo ""
echo "Contoh penggunaan:"
echo "  sudo web-backup     # Untuk melakukan backup manual"
echo "  sudo web-restore    # Untuk melakukan restore"
if [ -f "/usr/local/bin/restore_auto.py" ]; then
    echo "  sudo restore_auto.py --auto    # Untuk melakukan restore otomatis"
fi
echo ""
echo "Terima kasih telah menggunakan sistem backup dan restore ini."

detect_wazuh_version() {
    if [ -f "/var/ossec/bin/wazuh-control" ]; then
        WAZUH_VERSION=$(/var/ossec/bin/wazuh-control info | grep "Wazuh" | awk '{print $3}')
        info "Versi Wazuh terdeteksi: $WAZUH_VERSION"
    elif [ -f "/var/ossec/bin/ossec-control" ]; then
        # Coba deteksi dengan cara lain
        WAZUH_VERSION=$(/var/ossec/bin/ossec-control info | grep "OSSEC" | awk '{print $2}')
        info "Versi OSSEC/Wazuh terdeteksi: $WAZUH_VERSION"
    else
        warning "Tidak dapat mendeteksi versi Wazuh. Menggunakan konfigurasi default."
        WAZUH_VERSION="unknown"
    fi
}

detect_config_format() {
    # Cek format konfigurasi Wazuh (berbeda antara versi)
    if grep -q "<rules>" "/var/ossec/etc/ossec.conf"; then
        CONFIG_FORMAT="new"
        info "Format konfigurasi terdeteksi: format baru (4.x+)"
    else
        CONFIG_FORMAT="old"
        info "Format konfigurasi terdeteksi: format lama (3.x)"
    fi
} 