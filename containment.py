#!/usr/bin/env python3

import os
import sys
import json
import logging
import subprocess
from datetime import datetime
import ipaddress # Untuk validasi IP
import shutil # Untuk operasi file seperti copy
import glob # Untuk mencari file backup saat disable maintenance mode

# Konfigurasi logging
LOG_FILE = "/var/log/wazuh/active-response/containment.log"

try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
except OSError as e:
    print(f"Warning: Tidak dapat membuat direktori log {os.path.dirname(LOG_FILE)}. Error: {e}", file=sys.stderr)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

CONFIG_FILE = "/etc/web-backup/config.conf"

class ContainmentManager:
    def __init__(self):
        self.config = self._load_config()
        self.web_dir = self.config.get("WEB_DIR")

        if not self.web_dir or not os.path.isdir(self.web_dir):
            msg = f"WEB_DIR ('{self.web_dir}') tidak valid atau tidak ditemukan dalam konfigurasi: {CONFIG_FILE}."
            logger.error(msg)
            raise ValueError(msg)

        self.maintenance_page_filename = "maintenance.html"
        self.index_filename = "index.html" # Default, bisa disesuaikan jika perlu

        self.maintenance_page_source_path = os.path.join(self.web_dir, self.maintenance_page_filename)
        self.live_index_path = os.path.join(self.web_dir, self.index_filename)
        # Pola backup yang lebih dinamis akan digunakan di disable_maintenance_mode

        self.blocked_ips_file = "/etc/wazuh/blocked_ips.txt"
        try:
            os.makedirs(os.path.dirname(self.blocked_ips_file), exist_ok=True)
        except OSError as e:
            logger.warning(f"Tidak dapat membuat direktori untuk blocked_ips_file ({self.blocked_ips_file}): {e}")

    def _load_config(self):
        """Memuat konfigurasi dari file."""
        config = {}
        if not os.path.exists(CONFIG_FILE):
            logger.error(f"File konfigurasi {CONFIG_FILE} tidak ditemukan.")
            return config # Kembalikan dict kosong, fungsi dependen harus menangani config yang hilang

        try:
            with open(CONFIG_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and '=' in line and not line.startswith('#'):
                        line_content = line.split('#', 1)[0].strip()
                        if not line_content:
                            continue
                        key, value = line_content.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"\'')
                        config[key] = value
        except Exception as e:
            logger.error(f"Gagal membaca file konfigurasi {CONFIG_FILE}: {e}")
        return config

    def _is_ip_blocked(self, ip):
        """Memeriksa apakah IP sudah diblokir menggunakan iptables."""
        try:
            result = subprocess.run(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'],
                                 capture_output=True, check=False)
            return result.returncode == 0
        except FileNotFoundError:
            logger.error("Perintah 'iptables' tidak ditemukan.")
            return False
        except Exception as e:
            logger.error(f"Error saat memeriksa status blokir IP {ip} dengan iptables: {e}")
            return False

    def block_ip(self, ip):
        """Memblokir IP menggunakan iptables dan mencatatnya."""
        logger.info(f"Mencoba memblokir IP: {ip}")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error(f"Format IP tidak valid: {ip}")
            return False

        if self._is_ip_blocked(ip):
            logger.info(f"IP {ip} sudah diblokir sebelumnya.")
            return True

        try:
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True, capture_output=True, text=True)
            logger.info(f"IP {ip} berhasil diblokir menggunakan iptables.")

            try:
                blocked_ips = set()
                if os.path.exists(self.blocked_ips_file):
                    with open(self.blocked_ips_file, 'r') as f:
                        for line_ip in f:
                            blocked_ips.add(line_ip.strip())
                
                if ip not in blocked_ips:
                    with open(self.blocked_ips_file, 'a') as f:
                        f.write(f"{ip}\n")
                    logger.info(f"IP {ip} ditambahkan ke {self.blocked_ips_file}")
                else:
                    logger.info(f"IP {ip} sudah ada di {self.blocked_ips_file}, tidak ditambahkan lagi.")

            except IOError as e:
                logger.error(f"Gagal menulis ke file blocked_ips {self.blocked_ips_file}: {e}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Gagal memblokir IP {ip} menggunakan iptables: {e}. stderr: {e.stderr}")
            return False
        except FileNotFoundError:
            logger.error("Perintah 'iptables' tidak ditemukan. Tidak dapat memblokir IP.")
            return False

    def enable_maintenance_mode(self):
        """Mengaktifkan mode maintenance dengan mengganti file index."""
        logger.info(f"Mencoba mengaktifkan mode maintenance untuk direktori: {self.web_dir}")

        if not os.path.exists(self.maintenance_page_source_path):
            logger.error(f"File sumber halaman maintenance '{self.maintenance_page_source_path}' tidak ditemukan.")
            logger.error("Pastikan file maintenance.html sudah di-deploy ke direktori web oleh skrip instalasi.")
            return False

        try:
            if os.path.exists(self.live_index_path):
                # Membuat nama backup yang unik dengan timestamp
                backup_live_index_path = os.path.join(self.web_dir, f"{self.index_filename}.bak_containment_{datetime.now().strftime('%Y%m%d%H%M%S%f')}")
                shutil.copy2(self.live_index_path, backup_live_index_path)
                logger.info(f"File index utama '{self.live_index_path}' berhasil di-backup ke '{backup_live_index_path}'.")
            else:
                logger.warning(f"File index utama '{self.live_index_path}' tidak ditemukan. Akan tetap menempatkan halaman maintenance.")

            shutil.copy2(self.maintenance_page_source_path, self.live_index_path)
            logger.info(f"Mode maintenance berhasil diaktifkan. '{self.live_index_path}' sekarang menampilkan halaman maintenance.")
            return True
        except Exception as e:
            logger.error(f"Gagal mengaktifkan mode maintenance: {e}", exc_info=True)
            return False

    def disable_maintenance_mode(self): # Fungsi ini mungkin tidak dipanggil secara otomatis oleh Wazuh dalam alur ini
        """Menonaktifkan mode maintenance dengan mengembalikan index.html dari backup terakhir."""
        logger.info("Mencoba menonaktifkan mode maintenance.")
        
        backup_pattern = os.path.join(self.web_dir, f"{self.index_filename}.bak_containment_*")
        list_of_backups = glob.glob(backup_pattern)
        if not list_of_backups:
            logger.error(f"Tidak ada file backup index dengan pola '{backup_pattern}' ditemukan. Tidak dapat menonaktifkan mode maintenance.")
            return False

        try:
            latest_backup_file = max(list_of_backups, key=os.path.getmtime)
            logger.info(f"Menggunakan file backup index terbaru: {latest_backup_file}")

            shutil.copy2(latest_backup_file, self.live_index_path)
            logger.info(f"Mode maintenance berhasil dinonaktifkan. '{self.live_index_path}' dipulihkan dari '{latest_backup_file}'.")
            # Pertimbangkan untuk menghapus backup setelah pemulihan, atau biarkan untuk audit
            # os.remove(latest_backup_file)
            # logger.info(f"File backup '{latest_backup_file}' telah dihapus.")
            return True
        except Exception as e:
            logger.error(f"Gagal menonaktifkan mode maintenance: {e}", exc_info=True)
            return False

    def process_wazuh_alert(self, alert_data_str):
        """Memproses alert dari Wazuh dan mengambil tindakan containment."""
        logger.info("Menerima data alert dari Wazuh.")
        try:
            alert = json.loads(alert_data_str)
            logger.debug(f"Data alert yang di-parse: {alert}")
        except json.JSONDecodeError as e:
            logger.error(f"Format data alert Wazuh tidak valid (JSONDecodeError): {e}. Data: {alert_data_str[:200]}...")
            return False

        rule_id = alert.get('rule', {}).get('id')
        src_ip = alert.get('data', {}).get('srcip')
        description = alert.get('rule', {}).get('description', 'N/A')

        logger.info(f"Memproses alert Wazuh - Rule ID: {rule_id}, Deskripsi: {description}, Source IP: {src_ip if src_ip else 'N/A'}")

        actions_performed_summary = []

        # Logika berdasarkan rule_id (sesuaikan dengan kebutuhan Anda)
        # Contoh: Rule untuk defacement atau perubahan file mencurigakan
        deface_rule_ids = self.config.get("DEFACE_RULE_IDS", "550,554,5501,5502,5503,5504,100001,100002").split(',')
        attack_rule_ids = self.config.get("ATTACK_RULE_IDS", "5710,5712,5715,5760,100003,100004").split(',')


        if rule_id in deface_rule_ids:
            logger.info(f"Rule ID {rule_id} (potensi defacement) terdeteksi, mengambil tindakan containment.")
            if self.enable_maintenance_mode():
                actions_performed_summary.append("ModeMaintenanceDiaktifkan")
            if src_ip:
                if self.block_ip(src_ip):
                    actions_performed_summary.append(f"IPBlocked({src_ip})")
            else:
                logger.info("Tidak ada source IP (srcip) dalam alert defacement, tidak ada IP yang diblokir.")

        elif rule_id in attack_rule_ids: # Contoh rule ID untuk serangan lain (misal, brute force)
            logger.info(f"Rule ID {rule_id} (potensi serangan) terdeteksi, mencoba memblokir IP jika ada.")
            if src_ip:
                if self.block_ip(src_ip):
                    actions_performed_summary.append(f"IPBlocked({src_ip})")
            else:
                logger.info("Tidak ada source IP (srcip) dalam alert serangan, tidak ada IP yang diblokir.")
        else:
            logger.info(f"Tidak ada tindakan containment spesifik yang dikonfigurasi untuk rule ID {rule_id}.")

        if actions_performed_summary:
            logger.info(f"Tindakan containment yang dilakukan: {', '.join(actions_performed_summary)}")
        else:
            logger.info("Tidak ada tindakan containment yang dilakukan atau semua gagal untuk alert ini.")
        
        # Skrip AR biasanya mengembalikan 0 untuk sukses, non-zero untuk gagal.
        # Keberhasilan di sini berarti skrip berjalan tanpa error fatal, bukan tentu semua tindakan containment berhasil.
        return True # Atau evaluasi keberhasilan actions_performed_summary jika perlu

def main():
    alert_data_str = sys.stdin.read()

    if not alert_data_str:
        logger.warning("Tidak ada data alert yang diterima dari stdin.")
        sys.exit(1)

    try:
        containment_manager = ContainmentManager()
        containment_manager.process_wazuh_alert(alert_data_str)
        sys.exit(0) # Sukses jika proses alert selesai tanpa error fatal di manager
    except ValueError as e:
        logger.critical(f"Inisialisasi ContainmentManager gagal: {e}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Terjadi error tak terduga pada level main: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
