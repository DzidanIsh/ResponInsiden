#!/usr/bin/env python3

import os
import sys
import json
import logging
import shutil
import hashlib
import magic
import re
from datetime import datetime
from pathlib import Path
import subprocess
import yara
import clamd

# Konfigurasi logging
logging.basicConfig(
    filename='/var/log/wazuh/eradication.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class EradicationManager:
    def __init__(self):
        self.quarantine_dir = "/var/quarantine/web"
        self.yara_rules_dir = "/etc/wazuh/yara_rules"
        self.clamd_socket = "/var/run/clamav/clamd.ctl"
        self.suspicious_patterns = [
            r'(?i)(eval\s*\(|base64_decode|gzinflate|str_rot13|preg_replace.*\/e)',
            r'(?i)(system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\()',
            r'(?i)(file_get_contents\s*\(|file_put_contents\s*\()',
            r'(?i)(chmod\s*\(|chown\s*\(|chgrp\s*\()',
            r'(?i)(wget\s*\(|curl_exec\s*\(|file_get_contents\s*\()',
            r'(?i)(phpinfo\s*\(|php_uname\s*\()',
            r'(?i)(\$_GET|\$_POST|\$_REQUEST|\$_FILES)',
            r'(?i)(document\.write\s*\(|document\.location)',
            r'(?i)(onload\s*=|onerror\s*=|onmouseover\s*=)',
            r'(?i)(iframe\s*|script\s*|javascript:)'
        ]
        
    def setup_quarantine(self):
        """Menyiapkan direktori karantina"""
        try:
            if not os.path.exists(self.quarantine_dir):
                os.makedirs(self.quarantine_dir, mode=0o750)
                logging.info(f"Direktori karantina dibuat di {self.quarantine_dir}")
            return True
        except Exception as e:
            logging.error(f"Gagal membuat direktori karantina: {str(e)}")
            return False

    def calculate_file_hash(self, file_path):
        """Menghitung hash SHA-256 dari file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Gagal menghitung hash file {file_path}: {str(e)}")
            return None

    def scan_with_clamav(self, file_path):
        """Scan file menggunakan ClamAV"""
        try:
            cd = clamd.ClamdUnixSocket(self.clamd_socket)
            result = cd.scan(file_path)
            return result
        except Exception as e:
            logging.error(f"Gagal melakukan scan ClamAV: {str(e)}")
            return None

    def scan_with_yara(self, file_path):
        """Scan file menggunakan YARA rules"""
        try:
            matches = []
            for rule_file in os.listdir(self.yara_rules_dir):
                if rule_file.endswith('.yar'):
                    rule_path = os.path.join(self.yara_rules_dir, rule_file)
                    rules = yara.compile(rule_path)
                    matches.extend(rules.match(file_path))
            return matches
        except Exception as e:
            logging.error(f"Gagal melakukan scan YARA: {str(e)}")
            return None

    def check_suspicious_content(self, file_path):
        """Memeriksa konten mencurigakan dalam file"""
        try:
            if not os.path.isfile(file_path):
                return False

            # Cek tipe file
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)
            
            # Hanya scan file teks dan script
            if not file_type.startswith(('text/', 'application/x-php', 'application/javascript')):
                return False

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            for pattern in self.suspicious_patterns:
                if re.search(pattern, content):
                    logging.warning(f"Pola mencurigakan ditemukan di {file_path}: {pattern}")
                    return True
                    
            return False
        except Exception as e:
            logging.error(f"Gagal memeriksa konten file {file_path}: {str(e)}")
            return False

    def quarantine_file(self, file_path):
        """Memindahkan file ke karantina dan membuatnya read-only"""
        try:
            if not os.path.exists(file_path):
                logging.error(f"File tidak ditemukan: {file_path}")
                return False

            # Buat nama file karantina
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_name = os.path.basename(file_path)
            quarantine_name = f"{timestamp}_{file_name}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)

            # Pindahkan file ke karantina
            shutil.move(file_path, quarantine_path)
            
            # Buat file read-only
            os.chmod(quarantine_path, 0o400)
            
            # Catat metadata
            metadata = {
                'original_path': file_path,
                'quarantine_path': quarantine_path,
                'timestamp': timestamp,
                'file_hash': self.calculate_file_hash(quarantine_path),
                'file_type': magic.Magic(mime=True).from_file(quarantine_path)
            }
            
            # Simpan metadata
            metadata_path = f"{quarantine_path}.meta"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=4)
            
            logging.info(f"File berhasil dikarantina: {file_path} -> {quarantine_path}")
            return True
        except Exception as e:
            logging.error(f"Gagal mengkarantina file {file_path}: {str(e)}")
            return False

    def scan_directory(self, directory):
        """Scan seluruh direktori untuk file yang mencurigakan"""
        try:
            suspicious_files = []
            
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip file di direktori karantina
                    if self.quarantine_dir in file_path:
                        continue
                        
                    # Cek konten mencurigakan
                    if self.check_suspicious_content(file_path):
                        suspicious_files.append(file_path)
                        continue
                        
                    # Scan dengan ClamAV
                    clamav_result = self.scan_with_clamav(file_path)
                    if clamav_result and any(status == 'FOUND' for status in clamav_result.values()):
                        suspicious_files.append(file_path)
                        continue
                        
                    # Scan dengan YARA
                    yara_matches = self.scan_with_yara(file_path)
                    if yara_matches:
                        suspicious_files.append(file_path)
                        continue
            
            return suspicious_files
        except Exception as e:
            logging.error(f"Gagal melakukan scan direktori {directory}: {str(e)}")
            return []

    def process_wazuh_alert(self, alert_data):
        """Memproses alert dari Wazuh dan melakukan eradikasi"""
        try:
            # Parse alert data
            alert = json.loads(alert_data)
            
            # Ekstrak informasi penting
            affected_file = alert.get('data', {}).get('file')
            affected_dir = alert.get('data', {}).get('directory')
            
            if not affected_file and not affected_dir:
                logging.error("Tidak ada file atau direktori yang terpengaruh dalam alert")
                return False
            
            # Setup karantina
            if not self.setup_quarantine():
                return False
            
            # Jika ada file spesifik
            if affected_file:
                if self.check_suspicious_content(affected_file):
                    self.quarantine_file(affected_file)
            
            # Jika ada direktori
            if affected_dir:
                suspicious_files = self.scan_directory(affected_dir)
                for file in suspicious_files:
                    self.quarantine_file(file)
            
            return True
        except json.JSONDecodeError:
            logging.error("Format alert data tidak valid")
            return False
        except Exception as e:
            logging.error(f"Error saat memproses alert: {str(e)}")
            return False

def main():
    # Inisialisasi EradicationManager
    eradication = EradicationManager()
    
    # Baca alert data dari stdin
    alert_data = sys.stdin.read()
    
    if alert_data:
        eradication.process_wazuh_alert(alert_data)
    else:
        logging.error("Tidak ada data alert yang diterima")

if __name__ == "__main__":
    main() 