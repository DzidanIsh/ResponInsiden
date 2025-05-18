#!/bin/bash

# Script Instalasi untuk Server Monitoring (Backup Repository)
# -------------------------------------------------------------

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

# Fungsi untuk mengatur Git di direktori backup
function setup_git_repository {
    local dir="$1"
    local user="$2"
    
    # Masuk ke direktori backup
    cd "$dir" || error_exit "Gagal masuk ke direktori $dir"
    
    # Hapus konfigurasi Git sebelumnya jika ada (untuk mencegah error)
    if [ -d "$dir/.git" ]; then
        info_msg "Menghapus repository Git yang sudah ada di $dir untuk reinisialisasi..."
        rm -rf "$dir/.git"
    fi
    
    # Inisialisasi repository Git kosong
    info_msg "Menginisialisasi repository Git kosong di $dir..."
    git init --bare || error_exit "Gagal menginisialisasi repository Git"
    
    # Ubah kepemilikan jika pengguna ditentukan
    if [ ! -z "$user" ]; then
        chown -R "$user":"$user" "$dir" || 
            error_exit "Gagal mengubah kepemilikan direktori $dir"
    fi
    
    success_msg "Repository Git berhasil diinisialisasi di $dir"
}

# Banner
echo "================================================================="
echo "      INSTALASI SERVER MONITORING ANTI-DEFACEMENT               "
echo "================================================================="
echo ""

# Verifikasi bahwa script dijalankan sebagai root
if [ "$(id -u)" -ne 0 ]; then
    error_exit "Script ini harus dijalankan sebagai root."
fi

# Periksa apakah git terinstall
command -v git >/dev/null 2>&1 || {
    info_msg "Git tidak ditemukan. Menginstall Git..."
    apt-get update
    apt-get install -y git || error_exit "Gagal menginstall Git."
}

# Tentukan direktori untuk menyimpan backup
echo "Menentukan direktori untuk menyimpan backup..."
read -p "Masukkan path direktori backup (default: /var/backup/web): " BACKUP_DIR
BACKUP_DIR=${BACKUP_DIR:-/var/backup/web}

# Buat direktori backup jika belum ada
if [ ! -d "$BACKUP_DIR" ]; then
    info_msg "Membuat direktori backup: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR" || error_exit "Gagal membuat direktori $BACKUP_DIR"
fi

# Membuat pengguna khusus untuk backup (untuk keamanan yang lebih baik)
echo ""
echo "Pengaturan Pengguna Backup"
echo "-------------------------"
read -p "Apakah Anda ingin membuat pengguna khusus untuk backup? (y/n, default: y): " CREATE_USER
CREATE_USER=${CREATE_USER:-y}

if [ "$CREATE_USER" = "y" ] || [ "$CREATE_USER" = "Y" ]; then
    read -p "Masukkan nama pengguna untuk backup (default: wazuh): " BACKUP_USER
    BACKUP_USER=${BACKUP_USER:-wazuh}
    
    # Periksa apakah pengguna sudah ada
    if id "$BACKUP_USER" &>/dev/null; then
        info_msg "Pengguna $BACKUP_USER sudah ada."
    else
        info_msg "Membuat pengguna $BACKUP_USER..."
        useradd -m -s /bin/bash "$BACKUP_USER" || error_exit "Gagal membuat pengguna $BACKUP_USER"
        
        # Buat password untuk pengguna
        echo "Masukkan password untuk pengguna $BACKUP_USER:"
        passwd "$BACKUP_USER" || error_exit "Gagal mengatur password untuk pengguna $BACKUP_USER"
    fi
    
    # Inisialisasi repository Git
    setup_git_repository "$BACKUP_DIR" "$BACKUP_USER"
    
    # Mengatur izin akses
    chmod -R 750 "$BACKUP_DIR" || error_exit "Gagal mengatur izin akses direktori $BACKUP_DIR"
    
    # Membuat direktori SSH jika belum ada
    SSH_DIR="/home/$BACKUP_USER/.ssh"
    if [ ! -d "$SSH_DIR" ]; then
        mkdir -p "$SSH_DIR"
        touch "$SSH_DIR/authorized_keys"
        chmod 700 "$SSH_DIR"
        chmod 600 "$SSH_DIR/authorized_keys"
        chown -R "$BACKUP_USER":"$BACKUP_USER" "$SSH_DIR"
    fi
    
    # Tambahkan informasi untuk konfigurasi SSH
    echo ""
    echo "Pengaturan SSH untuk Server Web"
    echo "-------------------------------"
    echo "Untuk mengaktifkan koneksi dari server web, Anda perlu:"
    echo "1. Menghasilkan kunci SSH di server web:"
    echo "   ssh-keygen -t rsa -b 4096 -C \"backup@web-server\""
    echo ""
    echo "2. Menambahkan kunci publik ke file authorized_keys pengguna $BACKUP_USER di server ini:"
    echo "   Di server web, tampilkan kunci publik: cat ~/.ssh/id_rsa.pub"
    echo "   Di server ini, tambahkan kunci ke: $SSH_DIR/authorized_keys"
    echo ""
    echo "Atau, Anda dapat menjalankan perintah berikut di server web:"
    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    IP_ADDRESS=${IP_ADDRESS:-192.168.92.10}
    echo "   ssh-copy-id $BACKUP_USER@$IP_ADDRESS"
else
    # Jika tidak membuat pengguna khusus, tetap inisialisasi Git repo
    setup_git_repository "$BACKUP_DIR" ""
fi

# Konfigurasi untuk Monitoring Web Defacement (opsional)
echo ""
echo "Konfigurasi Monitoring Web Defacement"
echo "------------------------------------"
read -p "Apakah Anda ingin menginstal Wazuh Agent untuk monitoring? (y/n, default: n): " INSTALL_WAZUH
INSTALL_WAZUH=${INSTALL_WAZUH:-n}

if [ "$INSTALL_WAZUH" = "y" ] || [ "$INSTALL_WAZUH" = "Y" ]; then
    info_msg "Menginstal Wazuh Agent..."
    
    # Tambahkan repository Wazuh
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
    
    # Update dan install Wazuh Agent
    apt-get update
    apt-get install -y wazuh-agent || error_exit "Gagal menginstall Wazuh Agent"
    
    # Konfigurasi Wazuh Manager
    read -p "Masukkan alamat IP Wazuh Manager (default: 192.168.92.10): " WAZUH_MANAGER
    WAZUH_MANAGER=${WAZUH_MANAGER:-192.168.92.10}
    read -p "Masukkan grup untuk Wazuh Agent (default: default): " WAZUH_GROUP
    WAZUH_GROUP=${WAZUH_GROUP:-default}
    
    # Konfigurasi Wazuh Agent
    sed -i "s/^MANAGER_IP=.*/MANAGER_IP=\"$WAZUH_MANAGER\"/" /var/ossec/etc/ossec.conf
    sed -i "s/<server-ip>.*<\/server-ip>/<server-ip>$WAZUH_MANAGER<\/server-ip>/" /var/ossec/etc/ossec.conf
    
    # Mulai Wazuh Agent
    systemctl enable wazuh-agent
    systemctl start wazuh-agent
    
    success_msg "Wazuh Agent berhasil diinstal dan dikonfigurasi."
fi

# Konfigurasi Git Hooks untuk Notifikasi (opsional)
echo ""
echo "Konfigurasi Git Hook untuk Notifikasi"
echo "-----------------------------------"
read -p "Apakah Anda ingin mengatur notifikasi email setiap kali ada backup baru? (y/n, default: n): " SETUP_NOTIFICATION
SETUP_NOTIFICATION=${SETUP_NOTIFICATION:-n}

if [ "$SETUP_NOTIFICATION" = "y" ] || [ "$SETUP_NOTIFICATION" = "Y" ]; then
    read -p "Masukkan alamat email untuk notifikasi: " NOTIFY_EMAIL
    
    # Pastikan direktori hooks ada
    if [ ! -d "$BACKUP_DIR/hooks" ]; then
        mkdir -p "$BACKUP_DIR/hooks"
    fi
    
    # Buat script post-receive hook
    cat > "$BACKUP_DIR/hooks/post-receive" << EOF
#!/bin/bash
# Git hook untuk mengirim notifikasi email saat menerima backup baru

# Informasi backup
REPOSITORY="\$(basename \$(pwd))"
TIMESTAMP="\$(date +"%Y-%m-%d %H:%M:%S")"
SERVER="\$(hostname -f)"

# Dapatkan informasi commit terakhir
LAST_COMMIT=\$(git log -1 --pretty=format:"%h - %an, %ar : %s")

# Kirim email notifikasi
mail -s "Backup Baru di \$SERVER: \$REPOSITORY" $NOTIFY_EMAIL << EOM
Backup baru telah diterima di server monitoring.

Server: \$SERVER
Repository: \$REPOSITORY
Timestamp: \$TIMESTAMP
Commit terakhir: \$LAST_COMMIT

EOM
EOF

    # Atur izin untuk script hook
    chmod +x "$BACKUP_DIR/hooks/post-receive"
    
    # Ubah kepemilikan jika menggunakan pengguna khusus
    if [ "$CREATE_USER" = "y" ] || [ "$CREATE_USER" = "Y" ]; then
        chown "$BACKUP_USER":"$BACKUP_USER" "$BACKUP_DIR/hooks/post-receive"
    fi
    
    # Pastikan mail command tersedia
    command -v mail >/dev/null 2>&1 || {
        info_msg "Command 'mail' tidak ditemukan. Menginstall mailutils..."
        apt-get update
        apt-get install -y mailutils || error_exit "Gagal menginstall mailutils"
    }
    
    success_msg "Notifikasi email untuk backup baru telah dikonfigurasi."
fi

# Monitoring disk space (opsional)
echo ""
echo "Monitoring Disk Space"
echo "-------------------"
read -p "Apakah Anda ingin mengatur monitoring disk space untuk direktori backup? (y/n, default: y): " SETUP_DISK_MONITORING
SETUP_DISK_MONITORING=${SETUP_DISK_MONITORING:-y}

if [ "$SETUP_DISK_MONITORING" = "y" ] || [ "$SETUP_DISK_MONITORING" = "Y" ]; then
    # Membuat script monitoring disk space
    MONITOR_SCRIPT="/usr/local/bin/monitor-backup-disk.sh"
    
    cat > "$MONITOR_SCRIPT" << 'EOF'
#!/bin/bash

# Konfigurasi
BACKUP_DIR="$1"
THRESHOLD="$2"
EMAIL="$3"
HOSTNAME=$(hostname -f)

# Periksa penggunaan disk
USAGE=$(df -h "$BACKUP_DIR" | awk 'NR==2 {print $5}' | sed 's/%//')

# Jika penggunaan melebihi threshold, kirim notifikasi
if [ "$USAGE" -gt "$THRESHOLD" ]; then
    SUBJECT="[PERINGATAN] Penggunaan disk backup di $HOSTNAME mencapai $USAGE%"
    MESSAGE="Penggunaan disk pada direktori backup $BACKUP_DIR telah mencapai $USAGE%, melebihi threshold $THRESHOLD%.\n\nDetail penggunaan disk:\n\n$(df -h)"
    
    echo -e "$MESSAGE" | mail -s "$SUBJECT" "$EMAIL"
    
    echo "[$(date)] Peringatan: Penggunaan disk $USAGE% melebihi threshold $THRESHOLD%" >> /var/log/backup-monitor.log
fi
EOF

    # Atur izin eksekusi
    chmod +x "$MONITOR_SCRIPT"
    
    # Konfigurasi monitoring
    read -p "Masukkan threshold penggunaan disk dalam persen (default: 80): " DISK_THRESHOLD
    DISK_THRESHOLD=${DISK_THRESHOLD:-80}
    read -p "Masukkan alamat email untuk notifikasi disk space: " DISK_EMAIL
    
    # Tambahkan tugas cron untuk menjalankan monitoring setiap hari
    CRON_ENTRY="0 7 * * * $MONITOR_SCRIPT \"$BACKUP_DIR\" \"$DISK_THRESHOLD\" \"$DISK_EMAIL\" > /dev/null 2>&1"
    (crontab -l 2>/dev/null; echo "$CRON_ENTRY") | crontab -
    
    success_msg "Monitoring disk space untuk direktori backup telah dikonfigurasi."
fi

echo ""
echo "================================================================="
echo "      INSTALASI SERVER MONITORING BERHASIL DISELESAIKAN         "
echo "================================================================="
echo ""
echo "Informasi Konfigurasi:"
echo "---------------------"
echo "Direktori backup: $BACKUP_DIR"
if [ "$CREATE_USER" = "y" ] || [ "$CREATE_USER" = "Y" ]; then
    echo "Pengguna backup: $BACKUP_USER"
fi
echo ""
echo "Gunakan informasi berikut saat mengkonfigurasi server web:"
echo "1. IP Server Monitoring: ${IP_ADDRESS:-$(hostname -I | awk '{print $1}')}"
if [ "$CREATE_USER" = "y" ] || [ "$CREATE_USER" = "Y" ]; then
    echo "2. Username SSH: $BACKUP_USER"
fi
echo "3. Path direktori backup: $BACKUP_DIR"
echo ""
echo "Perintah untuk mengatur repository Git di server web:"
if [ "$CREATE_USER" = "y" ] || [ "$CREATE_USER" = "Y" ]; then
    echo "   git remote add monitoring $BACKUP_USER@${IP_ADDRESS:-$(hostname -I | awk '{print $1}')}:$BACKUP_DIR"
else
    echo "   git remote add monitoring root@${IP_ADDRESS:-$(hostname -I | awk '{print $1}')}:$BACKUP_DIR"
fi
echo ""
echo "Catatan penting:"
echo "- Jangan gunakan format 'ssh://user@host:port/path' karena dapat menyebabkan error"
echo "- Gunakan format 'user@host:path' untuk URL Git SSH"
echo "- Pastikan untuk melakukan ssh-copy-id terlebih dahulu dari server web"
echo ""
echo "Server telah siap untuk menerima backup dari server web."
echo "=================================================================" 