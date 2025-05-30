#!/usr/bin/env python3

import os
import sys
import json
import logging
import shutil
import hashlib
import re
from datetime import datetime
from pathlib import Path

try:
    import magic
except ImportError:
    magic = None
    logging.warning("Library 'python-magic' tidak terinstal. Deteksi tipe MIME mungkin kurang akurat.")

try:
    import yara
except ImportError:
    yara = None
    logging.warning("Library 'yara-python' tidak terinstal. Scan YARA akan dinonaktifkan.")

try:
    import pyclamd
except ImportError:
    pyclamd = None
    logging.warning("Library 'pyclamd' tidak terinstal. Scan ClamAV akan dinonaktifkan.")

try:
    import requests
except ImportError:
    requests = None
    logging.warning("Library 'requests' tidak terinstal. Integrasi YETI akan dinonaktifkan.")


# Konfigurasi logging
LOG_FILE = "/var/log/wazuh/active-response/eradication.log"
# (setup logging seperti sebelumnya)
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

class EradicationManager:
    def __init__(self):
        self.config = self._load_config()

        self.quarantine_dir = self.config.get("QUARANTINE_DIR", "/var/quarantine/web")
        self.yara_rules_dir = self.config.get("YARA_RULES_DIR", "/var/ossec/etc/rules/yara")
        self.clamd_socket_path = self.config.get("CLAMD_SOCKET", "/var/run/clamav/clamd.ctl")

        suspicious_patterns_str = self.config.get("ERADICATION_SUSPICIOUS_PATTERNS")
        # (definisi self.suspicious_patterns seperti sebelumnya)
        if suspicious_patterns_str:
            self.suspicious_patterns = [p.strip() for p in suspicious_patterns_str.split('|||')]
        else:
            self.suspicious_patterns = [
                r'(?i)(eval\s*\(base64_decode\s*\()', r'(?i)(passthru\s*\()', r'(?i)(shell_exec\s*\()',
                r'(?i)(system\s*\()', r'(?i)(exec\s*\()', r'(?i)(preg_replace\s*\(.*\/e\s*\))',
                r'(?i)(FilesMan|phpfm|P\.A\.S\.|\bWebShell\b|r57shell|c99shell)',
                r'(?i)(document\.write\s*\(\s*unescape\s*\()', r'(?i)(<iframe\s*src\s*=\s*["\']javascript:)',
                r'(?i)(fsockopen|pfsockopen)\s*\(',
            ]

        self.clamav_enabled = self._check_clamav_availability()
        self.yara_enabled = self._check_yara_availability()
        self.magic_enabled = magic is not None
        self.setup_quarantine_dir()

        # Konfigurasi YETI
        self.yeti_enabled = self.config.get("YETI_ENABLED", "false").lower() == "true"
        self.yeti_api_url = self.config.get("YETI_API_URL", "") # Contoh: https://yeti.example.com/api/
        self.yeti_api_key = self.config.get("YETI_API_KEY", "")
        self.yeti_session = None

        if self.yeti_enabled:
            if not requests:
                logger.error("Integrasi YETI diaktifkan tapi library 'requests' tidak ditemukan. Menonaktifkan integrasi.")
                self.yeti_enabled = False
            elif not self.yeti_api_url or not self.yeti_api_key:
                logger.error("Integrasi YETI diaktifkan tapi YETI_API_URL atau YETI_API_KEY tidak dikonfigurasi. Menonaktifkan integrasi.")
                self.yeti_enabled = False
            else:
                self.yeti_session = requests.Session()
                self.yeti_session.headers.update({'X-Api-Key': self.yeti_api_key, 'Accept': 'application/json'})
                logger.info("Integrasi YETI diaktifkan.")
        
        # Untuk menyimpan konteks alert saat ini
        self.current_alert_context = {}


    def _load_config(self):
        # (fungsi _load_config seperti sebelumnya)
        config = {}
        if not os.path.exists(CONFIG_FILE):
            logger.error(f"File konfigurasi {CONFIG_FILE} tidak ditemukan.")
            return config
        try:
            with open(CONFIG_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and '=' in line and not line.startswith('#'):
                        line_content = line.split('#', 1)[0].strip()
                        if not line_content: continue
                        key, value = line_content.split('=', 1)
                        config[key.strip()] = value.strip().strip('"\'')
        except Exception as e:
            logger.error(f"Gagal membaca file konfigurasi {CONFIG_FILE}: {e}")
        return config

    # --- Fungsi-fungsi pengecekan (ClamAV, YARA), setup karantina, hash ---
    # (salin dari versi sebelumnya: _check_clamav_availability, _check_yara_availability,
    #  setup_quarantine_dir, calculate_file_hash)

    def _check_clamav_availability(self):
        if pyclamd is None:
            return False
        try:
            cd = pyclamd.ClamdUnixSocket(path=self.clamd_socket_path)
            cd.ping()
            self.clamd_client = cd
            logger.info("Koneksi ke ClamAV berhasil via pyclamd.")
            return True
        except Exception as e:
            logger.warning(f"Gagal menghubungi ClamAV daemon: {e}")
            return False


    def _check_yara_availability(self):
        if yara is None: return False
        if not os.path.isdir(self.yara_rules_dir):
            logger.warning(f"Direktori YARA rules '{self.yara_rules_dir}' tidak ditemukan. Scan YARA dinonaktifkan.")
            return False
        try:
            rule_files = [os.path.join(self.yara_rules_dir, f) for f in os.listdir(self.yara_rules_dir) if f.endswith(('.yar', '.yara'))]
            if not rule_files:
                logger.warning(f"Tidak ada file rule YARA (.yar/.yara) ditemukan di '{self.yara_rules_dir}'. Scan YARA dinonaktifkan.")
                return False
            logger.info(f"Direktori YARA rules '{self.yara_rules_dir}' dan rules ditemukan. Scan YARA diaktifkan.")
            return True
        except Exception as e:
            logger.error(f"Error saat memeriksa YARA rules: {e}. Scan YARA dinonaktifkan.")
            return False

    def setup_quarantine_dir(self):
        try:
            if not os.path.exists(self.quarantine_dir):
                os.makedirs(self.quarantine_dir, mode=0o750)
                logger.info(f"Direktori karantina dibuat di {self.quarantine_dir}")
            os.chmod(self.quarantine_dir, 0o750)
            return True
        except Exception as e:
            logger.error(f"Gagal membuat atau mengatur izin direktori karantina '{self.quarantine_dir}': {e}")
            return False

    def calculate_file_hash(self, file_path, hash_alg="sha256"):
        h = hashlib.new(hash_alg)
        try:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk: break
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            logger.error(f"Gagal menghitung {hash_alg} hash untuk file {file_path}: {e}")
            return None
    # --- Akhir fungsi-fungsi pengecekan ---

    def _send_observable_to_yeti(self, value, type, description="", tags=None, source="EradicationScript"):
        """Mengirim observable ke YETI."""
        if not self.yeti_enabled or not self.yeti_session:
            return

        if tags is None:
            tags = []
        
        # Tambahkan tag default dari konteks alert jika ada
        tags.append(f"wazuh_agent:{self.current_alert_context.get('agent_name', 'N/A')}")
        tags.append(f"wazuh_rule:{self.current_alert_context.get('rule_id', 'N/A')}")
        tags = list(set(tags)) # Hapus duplikat

        # YETI biasanya mengharapkan list of observables
        # Endpoint API YETI bisa berbeda, ini contoh umum untuk YETI versi lama
        # atau /api/v2/observables/ untuk versi baru. Sesuaikan jika perlu.
        # Untuk kesederhanaan, kita buat satu observable per request.
        # YETI API V2 Observable structure:
        # { "value": "...", "type": "...", "tags": ["tag1"], "description": "..." }
        # Namun, biasanya dikirim sebagai list: { "observables": [ { ... } ] }

        payload = {
            "value": value,
            "type": type, # Tipe observable YETI (misalnya, 'File', 'Hash', 'Yara', 'String')
            "tags": [{"name": tag} for tag in tags if tag], # YETI V2 tags format
            "description": description,
            "source": source # Sumber observable
        }
        # Endpoint untuk membuat satu observable, sesuaikan dengan API YETI Anda
        # Contoh: /api/observables/ atau /api/v2/observables/
        # Beberapa API YETI mungkin butuh observable di dalam list, bahkan untuk satu item.
        # Misal: {"observables": [payload], "source": source}
        # Untuk YETI /api/entities/observables/ (jika menggunakan Yeti >=1.2 )
        # payload = {"value": value, "type": type, "tags": tags, "context": {"source": source, "description": description}}
        # Cek dokumentasi API YETI Anda untuk format yang benar.

        # Ini adalah contoh payload umum untuk endpoint yang menerima satu observable:
        # Atau jika API YETI Anda menerima { "observables": [payload_list] }:
        # api_payload = {"observables": [payload]}

        api_endpoint = self.yeti_api_url.strip('/') + "/observables/" # Pastikan path benar
        
        try:
            logger.info(f"Mengirim observable ke YETI: Type={type}, Value='{value[:100]}...'") # Log sebagian value
            # response = self.yeti_session.post(api_endpoint, json=api_payload) # Jika menggunakan list
            response = self.yeti_session.post(api_endpoint, json=payload) # Jika mengirim satu per satu
            response.raise_for_status() # Error jika status code 4xx atau 5xx
            logger.info(f"Observable berhasil dikirim ke YETI. Response: {response.status_code}")
            # logger.debug(f"YETI response content: {response.json()}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Gagal mengirim observable ke YETI: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Error tak terduga saat mengirim ke YETI: {e}", exc_info=True)


    def _enrich_yeti_with_finding(self, file_path, detection_method, details=""):
        """Mempersiapkan dan mengirim temuan ke YETI."""
        if not self.yeti_enabled:
            return

        common_tags = [detection_method.lower()]
        description_prefix = f"File '{file_path}' terdeteksi oleh {detection_method}"
        
        # 1. Kirim File Path
        self._send_observable_to_yeti(file_path, "File", # Atau 'Path' tergantung tipe di YETI Anda
                                     description=f"{description_prefix}. Detail: {details}",
                                     tags=common_tags + ["compromised_file_path"])

        # 2. Kirim Hash
        file_hash = self.calculate_file_hash(file_path)
        if file_hash:
            self._send_observable_to_yeti(file_hash, "Hash_SHA256", # Atau 'SHA256'
                                         description=f"SHA256 untuk {file_path} ({detection_method}: {details})",
                                         tags=common_tags + ["file_hash"])
        
        # 3. Kirim detail spesifik berdasarkan metode deteksi
        if detection_method == "ClamAV":
            # 'details' seharusnya berisi nama virus/signature
            self._send_observable_to_yeti(details, "Antivirus_Signature", # Atau 'String' atau 'ClamAV_Signature'
                                         description=f"Tanda tangan ClamAV '{details}' pada file '{file_path}'",
                                         tags=common_tags)
        elif detection_method == "YARA":
            # 'details' seharusnya berisi daftar nama rule yang cocok
            if isinstance(details, list): # Jika details adalah list nama rule
                for rule_name in details:
                    self._send_observable_to_yeti(rule_name, "Yara", # Atau 'Yara_Rule_Name'
                                                 description=f"Aturan YARA '{rule_name}' cocok pada file '{file_path}'",
                                                 tags=common_tags)
            else: # Jika details adalah string
                 self._send_observable_to_yeti(details, "Yara",
                                                 description=f"Aturan YARA '{details}' cocok pada file '{file_path}'",
                                                 tags=common_tags)
        elif detection_method == "RegexPattern":
            # 'details' seharusnya berisi pola regex yang cocok
            self._send_observable_to_yeti(details, "String", # Atau 'Regex_Pattern'
                                         description=f"Pola Regex '{details}' cocok pada file '{file_path}'",
                                         tags=common_tags)

    # --- Fungsi-fungsi scan (scan_with_clamav, scan_with_yara, check_suspicious_content) ---
    # (salin dari versi sebelumnya, tapi pastikan mereka me-return detail yang cukup untuk enrichment)
    def scan_with_clamav(self, file_path):
        if not self.clamav_enabled or not hasattr(self, 'clamd_client'):
            return None
        try:
            logger.debug(f"Memindai file '{file_path}' dengan ClamAV (pyclamd)...")
            result = self.clamd_client.scan_file(file_path)
            if result:
                status, virus_name = list(result.values())[0]
                if status == 'FOUND':
                    logger.warning(f"ClamAV FOUND threat: '{virus_name}' di file '{file_path}'")
                    return {'status': 'FOUND', 'details': virus_name}
            return {'status': 'OK', 'details': None}
        except Exception as e:
            logger.error(f"Error saat scan ClamAV via pyclamd: {e}")
            return None

    def scan_with_yara(self, file_path):
        if not self.yara_enabled: return []
        try:
            logger.debug(f"Memindai file '{file_path}' dengan YARA...")
            rule_files_map = {f'rule_{i}': os.path.join(self.yara_rules_dir, f)
                              for i, f in enumerate(os.listdir(self.yara_rules_dir))
                              if f.endswith(('.yar', '.yara'))}
            if not rule_files_map:
                self.yara_enabled = False
                return []
            rules = yara.compile(filepaths=rule_files_map)
            matches = rules.match(data=open(file_path, 'rb').read()) # Scan konten file
            if matches:
                matched_rules = [match.rule for match in matches]
                logger.warning(f"YARA MATCH: Aturan {matched_rules} cocok untuk file '{file_path}'")
            return matches # Mengembalikan list objek match YARA
        except yara.Error as e: # Tangkap error spesifik YARA
            logger.error(f"Error YARA saat memindai '{file_path}': {e}")
            if "compilation" in str(e).lower() or "syntax" in str(e).lower(): self.yara_enabled = False
            return []
        except Exception as e:
            logger.error(f"Error umum saat memindai '{file_path}' dengan YARA: {e}", exc_info=True)
            return []


    def check_suspicious_content(self, file_path): # Mengembalikan tuple (bool, detail_pattern_jika_match)
        try:
            if not os.path.isfile(file_path): return False, None
            content_to_scan = ""
            if self.magic_enabled:
                try:
                    file_type = magic.from_file(file_path, mime=True)
                    if not (file_type.startswith('text/') or 'javascript' in file_type or \
                            'php' in file_type or 'xml' in file_type or 'html' in file_type or 'x-empty' == file_type):
                        return False, None
                except magic.MagicException as e:
                    logger.warning(f"Error python-magic: {e}. Mengasumsikan teks.")

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content_to_scan = f.read(5*1024*1024) # Baca maks 5MB

            for pattern in self.suspicious_patterns:
                if re.search(pattern, content_to_scan):
                    logger.warning(f"Pola regex mencurigakan '{pattern}' ditemukan di file '{file_path}'")
                    return True, pattern # Kembalikan True dan polanya
            return False, None
        except Exception as e:
            logger.error(f"Gagal memeriksa konten file {file_path}: {e}", exc_info=True)
            return False, None
    # --- Akhir fungsi-fungsi scan ---

    def quarantine_file(self, file_path, detection_reason="Unknown"):
        # (fungsi quarantine_file seperti sebelumnya, tapi bisa menerima detection_reason untuk metadata)
        if not os.path.exists(file_path):
            logger.warning(f"File '{file_path}' tidak ditemukan saat akan dikarantina.")
            return False
        if not self.quarantine_dir or not os.path.isdir(self.quarantine_dir):
            logger.error(f"Direktori karantina '{self.quarantine_dir}' tidak valid.")
            return False

        try:
            original_file_path_abs = os.path.abspath(file_path)
            file_name = os.path.basename(original_file_path_abs)
            sanitized_original_path = re.sub(r'[^a-zA-Z0-9_.-]', '_', original_file_path_abs)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            quarantine_name = f"{timestamp}_{file_name}_{sanitized_original_path[:50]}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)

            logger.info(f"Mengkarantina file '{original_file_path_abs}' ke '{quarantine_path}' karena: {detection_reason}")
            shutil.move(original_file_path_abs, quarantine_path)
            os.chmod(quarantine_path, 0o400)
            logger.info(f"File berhasil dikarantina dan diatur read-only di '{quarantine_path}'")

            metadata = {
                'original_path': original_file_path_abs,
                'quarantine_path': quarantine_path,
                'quarantine_timestamp': timestamp,
                'file_hash_sha256': self.calculate_file_hash(quarantine_path, "sha256"),
                'file_size_bytes': os.path.getsize(quarantine_path),
                'file_type_mime': magic.from_file(quarantine_path, mime=True) if self.magic_enabled else "N/A",
                'detection_reason': detection_reason,
                'wazuh_context': self.current_alert_context
            }
            metadata_path = f"{quarantine_path}.meta"
            with open(metadata_path, 'w') as f_meta:
                json.dump(metadata, f_meta, indent=4)
            os.chmod(metadata_path, 0o400)
            logger.info(f"Metadata untuk file karantina disimpan di '{metadata_path}'")
            
            # Kirim info tentang file yang dikarantina ke YETI
            if self.yeti_enabled:
                 self._send_observable_to_yeti(value=original_file_path_abs, type="File",
                                              description=f"File dikarantina. Alasan: {detection_reason}",
                                              tags=["quarantined", detection_reason.split('(')[0].lower()])
                 if metadata['file_hash_sha256']:
                    self._send_observable_to_yeti(value=metadata['file_hash_sha256'], type="Hash_SHA256",
                                                 description=f"SHA256 dari file karantina {original_file_path_abs}. Alasan: {detection_reason}",
                                                 tags=["quarantined_hash", detection_reason.split('(')[0].lower()])
            return True
        except Exception as e:
            logger.error(f"Gagal mengkarantina file '{file_path}': {e}", exc_info=True)
            return False


    def _perform_all_scans_on_file(self, file_path):
        """ Melakukan semua jenis scan pada satu file dan mengembalikan tuple (bool_mencurigakan, string_alasan). """
        is_suspicious, detail = self.check_suspicious_content(file_path)
        if is_suspicious:
            return True, f"RegexPattern({detail})"
        
        clam_result = self.scan_with_clamav(file_path)
        if clam_result and clam_result.get('status') == 'FOUND':
            return True, f"ClamAV({clam_result.get('details', 'UnknownThreat')})"
        
        yara_matches_obj = self.scan_with_yara(file_path) # Ini mengembalikan list objek match
        if yara_matches_obj:
            # Ekstrak nama rule dari objek match
            rule_names = list(set([match.rule for match in yara_matches_obj])) # Ambil nama rule unik
            return True, f"YARA({','.join(rule_names)})" # Kirim sebagai string nama rule yang dipisahkan koma
        
        return False, "Clean"


    def scan_directory(self, directory_to_scan):
        # (fungsi scan_directory seperti sebelumnya, menggunakan _perform_all_scans_on_file)
        # Mengembalikan list tuple (file_path, reason)
        suspicious_findings = []
        if not os.path.isdir(directory_to_scan):
            logger.error(f"Direktori '{directory_to_scan}' tidak valid untuk dipindai.")
            return suspicious_findings

        logger.info(f"Memulai pemindaian direktori: {directory_to_scan}")
        for root, _, files in os.walk(directory_to_scan):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                if os.path.commonpath([self.quarantine_dir, file_path]) == self.quarantine_dir:
                    continue
                if file_name.endswith(".meta") and self.quarantine_dir in root:
                    continue
                
                is_suspicious, reason = self._perform_all_scans_on_file(file_path)
                if is_suspicious:
                    suspicious_findings.append((file_path, reason))
        
        if suspicious_findings:
            logger.info(f"Total {len(suspicious_findings)} temuan mencurigakan di direktori '{directory_to_scan}'.")
        else:
            logger.info(f"Tidak ada file mencurigakan ditemukan di direktori '{directory_to_scan}'.")
        return suspicious_findings


    def process_wazuh_alert(self, alert_data_str):
        logger.info("Menerima data alert dari Wazuh untuk eradikasi.")
        try:
            alert = json.loads(alert_data_str)
            logger.debug(f"Data alert yang di-parse: {alert}")
        except json.JSONDecodeError as e:
            logger.error(f"Format data alert Wazuh tidak valid: {e}. Data: {alert_data_str[:200]}...")
            return False

        self.current_alert_context = {
            'rule_id': alert.get('rule', {}).get('id'),
            'description': alert.get('rule', {}).get('description', 'N/A'),
            'agent_name': alert.get('agent', {}).get('name', 'N/A'),
            'agent_id': alert.get('agent', {}).get('id', 'N/A')
        }
        
        affected_file = alert.get('data', {}).get('file') or alert.get('syscheck', {}).get('path')
        affected_dir = alert.get('data', {}).get('directory')

        logger.info(f"Memproses alert eradikasi - Agent: {self.current_alert_context['agent_name']}, Rule ID: {self.current_alert_context['rule_id']}")
        logger.info(f"  File Terdampak: {affected_file if affected_file else 'N/A'}")
        logger.info(f"  Direktori Terdampak: {affected_dir if affected_dir else 'N/A'}")

        files_quarantined_count = 0

        if affected_file and os.path.exists(affected_file):
            if os.path.isfile(affected_file):
                is_suspicious, reason = self._perform_all_scans_on_file(affected_file)
                if is_suspicious:
                    logger.warning(f"File yang dilaporkan '{affected_file}' terdeteksi: {reason}.")
                    if self.yeti_enabled: # Kirim temuan sebelum karantina
                        self._enrich_yeti_with_finding(affected_file, reason.split('(')[0], details=reason.split('(')[1][:-1] if '(' in reason else reason)
                    if self.quarantine_file(affected_file, detection_reason=reason):
                        files_quarantined_count += 1
            else:
                logger.warning(f"Path '{affected_file}' ada tapi bukan file. Jika affected_dir kosong, akan diperlakukan sebagai direktori.")
                if not affected_dir: affected_dir = affected_file
        elif affected_file:
             logger.warning(f"File yang dilaporkan '{affected_file}' tidak ditemukan.")

        if affected_dir and os.path.isdir(affected_dir):
            suspicious_findings_list = self.scan_directory(affected_dir) # List of (path, reason)
            for f_path, reason in suspicious_findings_list:
                if self.yeti_enabled: # Kirim temuan sebelum karantina
                     self._enrich_yeti_with_finding(f_path, reason.split('(')[0], details=reason.split('(')[1][:-1] if '(' in reason else reason)
                if self.quarantine_file(f_path, detection_reason=reason):
                    files_quarantined_count += 1
        elif affected_dir :
            logger.warning(f"Direktori yang dilaporkan '{affected_dir}' tidak ditemukan.")

        if files_quarantined_count > 0:
            logger.info(f"Total {files_quarantined_count} file berhasil dikarantina.")
        else:
            logger.info("Tidak ada file yang dikarantina dalam proses ini.")
        return True

def main():
    # (main function seperti sebelumnya)
    alert_data_str = sys.stdin.read()
    if not alert_data_str:
        logger.warning("Tidak ada data alert yang diterima dari stdin.")
        sys.exit(1)

    try:
        eradication_manager = EradicationManager()
        eradication_manager.process_wazuh_alert(alert_data_str)
        sys.exit(0)
    except ValueError as e:
        logger.critical(f"Inisialisasi EradicationManager gagal: {e}", exc_info=True)
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Terjadi error tak terduga pada level main: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
