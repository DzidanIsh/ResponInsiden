#!/usr/bin/env python3

import os
import sys
import json
import logging
import subprocess
from datetime import datetime
import ipaddress
import shutil
from pathlib import Path

# Konfigurasi logging
logging.basicConfig(
    filename='/var/log/wazuh-containment.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class ContainmentManager:
    def __init__(self):
        self.maintenance_page = "/var/www/html/maintenance.html"
        self.original_index = "/var/www/html/index.html"
        self.backup_index = "/var/www/html/index.html.bak"
        self.web_root = "/var/www/html"
        self.blocked_ips_file = "/etc/wazuh/blocked_ips.txt"
        
    def remount_readonly(self):
        """Melakukan remount filesystem ke mode read-only"""
        try:
            # Cek apakah filesystem sudah dalam mode read-only
            if self._is_readonly():
                logging.info("Filesystem sudah dalam mode read-only")
                return True
                
            # Lakukan remount ke read-only
            subprocess.run(['mount', '-o', 'remount,ro', '/'], check=True)
            logging.info("Filesystem berhasil di-remount ke mode read-only")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Gagal melakukan remount read-only: {str(e)}")
            return False
            
    def _is_readonly(self):
        """Memeriksa apakah filesystem dalam mode read-only"""
        try:
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    if line.startswith('/dev/root') and 'ro' in line:
                        return True
            return False
        except Exception as e:
            logging.error(f"Error saat memeriksa status read-only: {str(e)}")
            return False

    def block_ip(self, ip):
        """Memblokir IP menggunakan iptables"""
        try:
            # Validasi format IP
            ipaddress.ip_address(ip)
            
            # Cek apakah IP sudah diblokir
            if self._is_ip_blocked(ip):
                logging.info(f"IP {ip} sudah diblokir sebelumnya")
                return True
                
            # Blokir IP menggunakan iptables
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            
            # Simpan IP yang diblokir ke file
            with open(self.blocked_ips_file, 'a') as f:
                f.write(f"{ip}\n")
                
            logging.info(f"IP {ip} berhasil diblokir")
            return True
        except ValueError:
            logging.error(f"Format IP tidak valid: {ip}")
            return False
        except subprocess.CalledProcessError as e:
            logging.error(f"Gagal memblokir IP {ip}: {str(e)}")
            return False
            
    def _is_ip_blocked(self, ip):
        """Memeriksa apakah IP sudah diblokir"""
        try:
            result = subprocess.run(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'], 
                                 capture_output=True)
            return result.returncode == 0
        except subprocess.CalledProcessError:
            return False

    def enable_maintenance_mode(self):
        """Mengaktifkan mode maintenance dengan mengganti index.html"""
        try:
            # Backup index.html jika belum ada
            if not os.path.exists(self.backup_index):
                shutil.copy2(self.original_index, self.backup_index)
                logging.info("Backup index.html berhasil dibuat")
            
            # Ganti index.html dengan halaman maintenance
            shutil.copy2(self.maintenance_page, self.original_index)
            logging.info("Mode maintenance berhasil diaktifkan")
            return True
        except Exception as e:
            logging.error(f"Gagal mengaktifkan mode maintenance: {str(e)}")
            return False

    def disable_maintenance_mode(self):
        """Menonaktifkan mode maintenance dengan mengembalikan index.html"""
        try:
            if os.path.exists(self.backup_index):
                shutil.copy2(self.backup_index, self.original_index)
                logging.info("Mode maintenance berhasil dinonaktifkan")
                return True
            else:
                logging.error("File backup index.html tidak ditemukan")
                return False
        except Exception as e:
            logging.error(f"Gagal menonaktifkan mode maintenance: {str(e)}")
            return False

    def process_wazuh_alert(self, alert_data):
        """Memproses alert dari Wazuh dan mengambil tindakan containment yang sesuai"""
        try:
            # Parse alert data
            alert = json.loads(alert_data)
            
            # Ekstrak informasi penting dari alert
            rule_id = alert.get('rule', {}).get('id')
            src_ip = alert.get('data', {}).get('srcip')
            
            # Log alert yang diterima
            logging.info(f"Menerima alert Wazuh - Rule ID: {rule_id}, Source IP: {src_ip}")
            
            # Ambil tindakan berdasarkan rule_id
            if rule_id in ['100001', '100002']:  # Contoh rule ID untuk defacement
                self.remount_readonly()
                if src_ip:
                    self.block_ip(src_ip)
                self.enable_maintenance_mode()
                
            elif rule_id in ['100003', '100004']:  # Contoh rule ID untuk serangan lain
                if src_ip:
                    self.block_ip(src_ip)
                    
            return True
        except json.JSONDecodeError:
            logging.error("Format alert data tidak valid")
            return False
        except Exception as e:
            logging.error(f"Error saat memproses alert: {str(e)}")
            return False

def main():
    # Inisialisasi ContainmentManager
    containment = ContainmentManager()
    
    # Baca alert data dari stdin
    alert_data = sys.stdin.read()
    
    if alert_data:
        containment.process_wazuh_alert(alert_data)
    else:
        logging.error("Tidak ada data alert yang diterima")

if __name__ == "__main__":
    main() 