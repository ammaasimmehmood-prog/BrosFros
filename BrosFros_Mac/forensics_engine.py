import os
import sqlite3
import shutil
import json
import base64
import re
import datetime
import hashlib
import tempfile
import xlsxwriter
import py7zr
from urllib.parse import urlparse, unquote
from collections import Counter
from Crypto.Cipher import AES
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

win32crypt = None

class BrowserArtifact:
    def __init__(self, browser_name, artifact_type, data):
        self.browser_name = browser_name
        self.artifact_type = artifact_type
        self.data = data

class ForensicEngine:
    def __init__(self):
        self.temp_dir = os.path.join(tempfile.gettempdir(), 'BrosFros_Analysis')
        self.browsers = self.detect_browsers()
        self.results = []
        self.case_details = {}
        self.permissions_cache = {}
        self.watchlist = []
        self.forensic_mode = False
        self.activity_log = []
        self.source_hashes = {}
        self.log_event("Engine Initialized", "System detection completed.")

    def hash_source_evidence(self, file_path, artifact_name):
        if not os.path.exists(file_path): return None
        try:
            md5, sha256 = hashlib.md5(), hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5.update(chunk); sha256.update(chunk)
            hash_str = f"MD5: {md5.hexdigest()}, SHA256: {sha256.hexdigest()}"
            self.source_hashes[file_path] = hash_str
            if self.forensic_mode:
                self.log_event("Evidence Hashed", f"Source: {artifact_name} | {hash_str}")
            return hash_str
        except Exception as e:
            self.log_event("Hash Error", f"Failed to hash {artifact_name}: {str(e)}")
            return None

    def log_event(self, action, details):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        step_num = len(self.activity_log) + 1
        self.activity_log.append({
            "Step": step_num,
            "Timestamp": timestamp,
            "Action": action,
            "Details": details
        })

    def cleanup_temp(self):
        self.log_event("Cleanup Started", "Removing temporary analysis files.")
        self._cleanup_temp(recreate=False)
        self.log_event("Cleanup Completed", "Temporary directory cleared.")

    def _cleanup_temp(self, recreate=True):
        if os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except Exception: pass
        if recreate and not self.forensic_mode:
            os.makedirs(self.temp_dir, exist_ok=True)

    def detect_browsers(self):
        return self._detect_browsers()

    def _detect_browsers(self):
        home = os.path.expanduser("~")
        lib_app_support = os.path.join(home, "Library", "Application Support")
        browser_paths = {
            'Chrome': os.path.join(lib_app_support, 'Google', 'Chrome'),
            'Edge': os.path.join(lib_app_support, 'Microsoft Edge'),
            'Firefox': os.path.join(lib_app_support, 'Firefox', 'Profiles'),
            'Opera': os.path.join(lib_app_support, 'com.operasoftware.Opera'),
            'Brave': os.path.join(lib_app_support, 'BraveSoftware', 'Brave-Browser'),
            'Safari': os.path.join(home, 'Library', 'Safari')
        }
        detected = []
        for name, path in browser_paths.items():
            if name == 'Firefox':
                if os.path.exists(path):
                    for profile in os.listdir(path):
                        if os.path.exists(os.path.join(path, profile, 'places.sqlite')):
                            detected.append({'name': name, 'path': os.path.join(path, profile)})
            elif os.path.exists(path):
                detected.append({'name': name, 'path': path})
        
        return detected

    def get_master_key(self, local_state_path):
        return None

    def decrypt_value(self, buff, master_key):
        if not buff: return ""
        return "<macOS Keychain Protected>"

    def _connect_db(self, path):
        if self.forensic_mode:
            return sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        return sqlite3.connect(path)

    def extract_location(self, url):
        if not url or not isinstance(url, str): return "N/A"
        map_patterns = [
            r'@(-?\d+\.\d+),(-?\d+\.\d+)',
            r'q=(-?\d+\.\d+),(-?\d+\.\d+)',
            r'll=(-?\d+\.\d+),(-?\d+\.\d+)'
        ]
        for pattern in map_patterns:
            match = re.search(pattern, url)
            if match:
                return f"Lat: {match.group(1)}, Lon: {match.group(2)}"
        
        if "maps" in url.lower() or "location" in url.lower():
            try:
                parsed = urlparse(url)
                if "place" in parsed.path:
                    parts = parsed.path.split("/")
                    for i, p in enumerate(parts):
                        if p == "place" and i+1 < len(parts):
                            return unquote(parts[i+1]).replace("+", " ")
            except Exception: pass
            
        return "N/A"

    def load_all_permissions(self):
        self.log_event("Permissions Scan", "Extracting web permissions from all browsers.")
        self.permissions_cache = {}
        for browser in self.browsers:
            name, path = browser['name'], browser['path']
            if name == 'Firefox':
                perm_db = os.path.join(path, "permissions.sqlite")
                if os.path.exists(perm_db):
                    try:
                        temp_db = os.path.join(self.temp_dir, f"temp_perms_{hash(path)}")
                        shutil.copy2(perm_db, temp_db)
                        conn = self._connect_db(temp_db); cursor = conn.cursor()
                        for origin, type, permission in cursor.execute("SELECT origin, type, permission FROM moz_perms"):
                            perm_val = "Allow" if permission == 1 else "Block" if permission == 2 else str(permission)
                            self.permissions_cache.setdefault(origin, []).append(f"{type}: {perm_val}")
                        conn.close()
                    except Exception: pass
            elif name != 'Internet Explorer' and path != 'Registry':
                profile_path = os.path.join(path, "Default")
                if not os.path.exists(profile_path) and os.path.exists(os.path.join(path, "History")): profile_path = path
                prefs_path = os.path.join(profile_path, "Preferences")
                if os.path.exists(prefs_path):
                    try:
                        with open(prefs_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        exceptions = data.get('profile', {}).get('content_settings', {}).get('exceptions', {})
                        for perm_type, sites in exceptions.items():
                            for site, settings in sites.items():
                                if site == '*': continue
                                perm_val = 'Allow' if settings.get('setting') == 1 else 'Block'
                                self.permissions_cache.setdefault(site, []).append(f"{perm_type}: {perm_val}")
                    except Exception: pass
        
        for origin, perms in self.permissions_cache.items():
            self.add_artifact('Browser', 'Web Permission', {
                'URL': origin,
                'Title': 'Permissions',
                'Value': ", ".join(perms),
                'Status': 'Active',
                'Deep': 'Yes',
                'Web Permissions': ", ".join(perms),
                'Session': 'Standard',
                'Location': self.extract_location(origin)
            })

    def get_permissions_for_url(self, url):
        if not url or not isinstance(url, str): return "None"
        try:
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            perms = self.permissions_cache.get(origin)
            if perms: return ", ".join(perms)
            origin_no_scheme = parsed.netloc
            perms = self.permissions_cache.get(origin_no_scheme)
            if perms: return ", ".join(perms)
        except Exception: pass
        return "None"

    def check_watchlist(self, data):
        match_type = "No"
        keywords = [k.lower() for k in self.watchlist] if self.watchlist else []
        dark_web_tlds = ['.onion', '.i2p']
        
        for val in data.values():
            val_str = str(val).lower()
            if keywords and any(kw in val_str for kw in keywords):
                match_type = "Yes"
            if any(tld in val_str for tld in dark_web_tlds):
                return "Yes (Dark Web Activity)"
                
        return match_type

    def add_artifact(self, browser_name, artifact_type, data):
        data['Watchlist Match'] = self.check_watchlist(data)
        if 'Session' not in data:
            data['Session'] = 'Standard'
        if 'Location' not in data:
            data['Location'] = self.extract_location(data.get('URL'))
        self.results.append(BrowserArtifact(browser_name, artifact_type, data))

    def process_firefox_history(self, path):
        history_db = os.path.join(path, "places.sqlite")
        if not os.path.exists(history_db): return
        self.hash_source_evidence(history_db, "Firefox History")
        temp_history = os.path.join(self.temp_dir, f"Firefox_History_{abs(hash(path))}")
        conn = None
        try:
            shutil.copy2(history_db, temp_history)
            conn = self._connect_db(temp_history); cursor = conn.cursor()
            query = "SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL"
            for url, title, visit_count, last_visit_date in cursor.execute(query):
                timestamp = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=last_visit_date)
                self.add_artifact('Firefox', 'History', {
                    'URL': url, 
                    'Title': title or "N/A", 
                    'Visit Count': visit_count, 
                    'Timestamp': timestamp, 
                    'Status': 'Live',
                    'Deep': 'No',
                    'Web Permissions': self.get_permissions_for_url(url),
                    'Session': 'Standard'
                })
        except Exception as e:
            self.log_event("Extraction Error", f"Firefox History: {str(e)}")
        finally:
            if conn: conn.close()

    def process_ie_typed_urls(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Internet Explorer\TypedURLs")
            for i in range(0, 100):
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    self.add_artifact('Internet Explorer', 'History', {
                        'URL': value, 
                        'Title': 'Typed URL', 
                        'Timestamp': 'N/A', 
                        'Status': 'Live',
                        'Deep': 'No',
                        'Web Permissions': 'None',
                        'Session': 'Standard'
                    })
                except OSError: break
        except Exception as e:
            self.log_event("Extraction Error", f"IE Typed URLs: {str(e)}")

    def process_history(self, browser_name, history_path, deep_scan=False):
        if not os.path.exists(history_path): return
        self.hash_source_evidence(history_path, f"{browser_name} History")
        temp_history = os.path.join(self.temp_dir, f"{browser_name}_History_{abs(hash(history_path))}")
        conn = None
        try:
            shutil.copy2(history_path, temp_history)
            conn = self._connect_db(temp_history); cursor = conn.cursor()
            # Build frequency map from visits table (may not exist in all Chromium forks)
            frequency_map = {}
            try:
                url_visits = [row[0] for row in cursor.execute("SELECT url FROM visits")]
                frequency_map = Counter(url_visits)
            except Exception:
                pass  # visits table may not exist or have different schema
            for url_id, url, title, visit_count, last_visit_time in cursor.execute("SELECT id, url, title, visit_count, last_visit_time FROM urls"):
                timestamp = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=last_visit_time)
                self.add_artifact(browser_name, 'History', {
                    'URL': url, 
                    'Title': title, 
                    'Visit Count': visit_count, 
                    'Timestamp': timestamp, 
                    'Status': 'Live', 
                    'Frequency': frequency_map.get(url_id, 0),
                    'Deep': 'No',
                    'Web Permissions': self.get_permissions_for_url(url),
                    'Session': 'Standard'
                })
        except Exception as e:
            self.log_event("Extraction Error", f"{browser_name} History: {str(e)}")
        finally:
            if conn: conn.close()
        if deep_scan: self.carve_deleted_urls(browser_name, temp_history)

    def process_downloads(self, browser_name, history_path):
        if not os.path.exists(history_path): return
        temp_db = os.path.join(self.temp_dir, f"{browser_name}_Downloads_{abs(hash(history_path))}")
        conn = None
        try:
            shutil.copy2(history_path, temp_db)
            conn = self._connect_db(temp_db); cursor = conn.cursor()
            for target_path, site_url, start_time in cursor.execute("SELECT target_path, site_url, start_time FROM downloads"):
                timestamp = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=start_time)
                self.add_artifact(browser_name, 'Download', {
                    'URL': site_url, 
                    'Title': os.path.basename(target_path), 
                    'Timestamp': timestamp, 
                    'Status': 'Downloaded', 
                    'Value': target_path,
                    'Deep': 'Yes',
                    'Web Permissions': self.get_permissions_for_url(site_url),
                    'Session': 'Standard'
                })
        except Exception as e:
            self.log_event("Extraction Error", f"{browser_name} Downloads: {str(e)}")
        finally:
            if conn: conn.close()

    def process_bookmarks(self, browser_name, bookmarks_path):
        if not os.path.exists(bookmarks_path): return
        self.hash_source_evidence(bookmarks_path, f"{browser_name} Bookmarks")
        try:
            with open(bookmarks_path, "r", encoding="utf-8") as f: data = json.load(f)
            def parse_bookmarks(nodes):
                for node in nodes:
                    if node['type'] == 'url':
                        self.add_artifact(browser_name, 'Bookmark', {
                            'URL': node['url'], 
                            'Title': node['name'], 
                            'Timestamp': 'N/A', 
                            'Status': 'Bookmarked',
                            'Deep': 'Yes',
                            'Web Permissions': self.get_permissions_for_url(node['url']),
                            'Session': 'Standard'
                        })
                    elif node['type'] == 'folder': parse_bookmarks(node['children'])
            parse_bookmarks(data['roots']['bookmark_bar']['children'])
            parse_bookmarks(data['roots']['other']['children'])
        except Exception as e:
            self.log_event("Extraction Error", f"{browser_name} Bookmarks: {str(e)}")

    def process_cookies(self, browser_name, cookies_path, local_state_path):
        if not os.path.exists(cookies_path): return
        self.hash_source_evidence(cookies_path, f"{browser_name} Cookies")
        master_key = self.get_master_key(local_state_path)
        temp_db = os.path.join(self.temp_dir, f"{browser_name}_Cookies_{abs(hash(cookies_path))}")
        conn = None
        try:
            shutil.copy2(cookies_path, temp_db)
            conn = self._connect_db(temp_db); cursor = conn.cursor()
            for host, name, value, enc_value in cursor.execute("SELECT host_key, name, value, encrypted_value FROM cookies"):
                if not value and enc_value and master_key:
                    value = self.decrypt_value(enc_value, master_key)
                self.add_artifact(browser_name, 'Cookie', {
                    'URL': host, 
                    'Title': name, 
                    'Value': value, 
                    'Status': 'Active Session',
                    'Deep': 'Yes',
                    'Web Permissions': self.get_permissions_for_url(host),
                    'Session': 'Standard'
                })
        except Exception as e:
            self.log_event("Extraction Error", f"{browser_name} Cookies: {str(e)}")
        finally:
            if conn: conn.close()

    def process_search_terms(self, browser_name, history_path):
        if not os.path.exists(history_path): return
        temp_db = os.path.join(self.temp_dir, f"{browser_name}_SearchTerms_{abs(hash(history_path))}")
        conn = None
        try:
            shutil.copy2(history_path, temp_db)
            conn = self._connect_db(temp_db); cursor = conn.cursor()
            for term, url in cursor.execute("SELECT term, url FROM keyword_search_terms JOIN urls ON keyword_search_terms.url_id = urls.id"):
                self.add_artifact(browser_name, 'Search Term', {
                    'URL': url, 
                    'Title': 'Search', 
                    'Value': term, 
                    'Status': 'Searched',
                    'Deep': 'Yes',
                    'Web Permissions': self.get_permissions_for_url(url),
                    'Session': 'Standard'
                })
        except Exception as e:
            self.log_event("Extraction Error", f"{browser_name} Search Terms: {str(e)}")
        finally:
            if conn: conn.close()

    def process_autofills(self, browser_name, web_data_path):
        if not os.path.exists(web_data_path): return
        self.hash_source_evidence(web_data_path, f"{browser_name} WebData")
        temp_db = os.path.join(self.temp_dir, f"{browser_name}_WebData_{abs(hash(web_data_path))}")
        conn = None
        try:
            shutil.copy2(web_data_path, temp_db)
            conn = self._connect_db(temp_db); cursor = conn.cursor()
            for name, value in cursor.execute("SELECT name, value FROM autofill"):
                self.add_artifact(browser_name, 'Autofill', {
                    'URL': 'N/A', 
                    'Title': name, 
                    'Value': value, 
                    'Status': 'Autofill Entry',
                    'Deep': 'Yes',
                    'Web Permissions': 'None',
                    'Session': 'Standard'
                })
        except Exception as e:
            self.log_event("Extraction Error", f"{browser_name} Autofills: {str(e)}")
        finally:
            if conn: conn.close()

    def carve_deleted_urls(self, browser_name, file_path):
        try:
            with open(file_path, "rb") as f: content = f.read()
            for match in re.finditer(rb'https?://[\w\-\._~:/?#[\]@!$&\'()*+,;=]+', content):
                try:
                    url = match.group(0).decode('utf-8', errors='ignore')
                    if len(url) > 10:
                        self.add_artifact(browser_name, 'Deleted History', {
                            'URL': url, 
                            'Title': '<Recovered>', 
                            'Visit Count': 0, 
                            'Timestamp': 'Unknown', 
                            'Status': 'Deleted (Recovered)', 
                            'Frequency': 0,
                            'Deep': 'Yes',
                            'Web Permissions': self.get_permissions_for_url(url),
                            'Session': 'Private (Recovered)'
                        })
                except Exception: continue
        except Exception as e:
            self.log_event("Extraction Error", f"{browser_name} Deleted URLs: {str(e)}")

    def process_credentials(self, browser_name, login_path, local_state_path):
        if not os.path.exists(login_path): return
        self.hash_source_evidence(login_path, f"{browser_name} LoginData")
        master_key = self.get_master_key(local_state_path)
        if not master_key: return
        temp_login_db = os.path.join(self.temp_dir, f"{browser_name}_LoginData_{abs(hash(login_path))}")
        conn = None
        try:
            shutil.copy2(login_path, temp_login_db)
            conn = self._connect_db(temp_login_db); cursor = conn.cursor()
            for url, username, enc_pass in cursor.execute("SELECT origin_url, username_value, password_value FROM logins"):
                password = self.decrypt_value(enc_pass, master_key)
                self.add_artifact(browser_name, 'Credential', {
                    'URL': url, 
                    'Username': username, 
                    'Password': password, 
                    'Decryption Status': 'Success' if password and "<Decryption Error>" not in password else 'Failed',
                    'Deep': 'No',
                    'Web Permissions': self.get_permissions_for_url(url),
                    'Session': 'Standard'
                })
        except Exception as e:
            self.log_event("Extraction Error", f"{browser_name} Credentials: {str(e)}")
        finally:
            if conn: conn.close()

    def process_extensions(self, browser_name, extensions_path):
        if not os.path.exists(extensions_path): return
        self.hash_source_evidence(extensions_path, f"{browser_name} Extensions")
        try:
            for ext_id in os.listdir(extensions_path):
                ext_dir = os.path.join(extensions_path, ext_id)
                if not os.path.isdir(ext_dir): continue
                for ver in os.listdir(ext_dir):
                    manifest_path = os.path.join(ext_dir, ver, "manifest.json")
                    if os.path.exists(manifest_path):
                        try:
                            with open(manifest_path, "r", encoding="utf-8") as f:
                                manifest = json.load(f)
                            name = manifest.get("name", "Unknown")
                            if isinstance(name, dict): name = str(name)
                            if isinstance(name, str) and name.startswith("__MSG_"): name = f"Localized: {ext_id}"
                            desc = manifest.get("description", "")
                            version = manifest.get("version", "Unknown")
                            self.add_artifact(browser_name, 'Extension', {
                                'URL': ext_id, 
                                'Title': name, 
                                'Value': f"Version: {version} | Desc: {desc}", 
                                'Status': 'Installed',
                                'Deep': 'Yes',
                                'Web Permissions': 'None',
                                'Session': 'Standard'
                            })
                        except Exception: pass
        except Exception as e:
            self.log_event("Extraction Error", f"{browser_name} Extensions: {str(e)}")

    def process_firefox_extensions(self, browser_name, profile_path):
        extensions_json = os.path.join(profile_path, "extensions.json")
        if not os.path.exists(extensions_json): return
        self.hash_source_evidence(extensions_json, f"{browser_name} Extensions")
        try:
            with open(extensions_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            addons = data.get("addons", [])
            for addon in addons:
                name = addon.get("defaultLocale", {}).get("name", addon.get("name", "Unknown"))
                desc = addon.get("defaultLocale", {}).get("description", addon.get("description", ""))
                version = addon.get("version", "Unknown")
                ext_id = addon.get("id", "Unknown")
                self.add_artifact(browser_name, 'Extension', {
                    'URL': ext_id, 
                    'Title': name, 
                    'Value': f"Version: {version} | Desc: {desc}", 
                    'Status': 'Installed' if addon.get("active") else 'Disabled',
                    'Deep': 'Yes',
                    'Web Permissions': 'None',
                    'Session': 'Standard'
                })
        except Exception as e:
            self.log_event("Extraction Error", f"{browser_name} Extensions: {str(e)}")

    def process_top_sites(self, browser_name, top_sites_path):
        if not os.path.exists(top_sites_path): return
        self.hash_source_evidence(top_sites_path, f"{browser_name} Top Sites")
        temp_db = os.path.join(self.temp_dir, f"{browser_name}_TopSites_{abs(hash(top_sites_path))}")
        conn = None
        try:
            shutil.copy2(top_sites_path, temp_db)
            conn = self._connect_db(temp_db); cursor = conn.cursor()
            for url, url_rank, title in cursor.execute("SELECT url, url_rank, title FROM top_sites ORDER BY url_rank ASC"):
                self.add_artifact(browser_name, 'Top Site', {
                    'URL': url, 
                    'Title': title, 
                    'Value': f"Rank: {url_rank}", 
                    'Status': 'Top Site',
                    'Deep': 'Yes',
                    'Web Permissions': self.get_permissions_for_url(url),
                    'Session': 'Standard'
                })
        except Exception as e:
            self.log_event("Extraction Error", f"{browser_name} Top Sites: {str(e)}")
        finally:
            if conn: conn.close()

    def process_network_predictor(self, browser_name, predictor_path):
        if not os.path.exists(predictor_path): return
        self.hash_source_evidence(predictor_path, f"{browser_name} Network Predictor")
        temp_db = os.path.join(self.temp_dir, f"{browser_name}_Predictor_{abs(hash(predictor_path))}")
        conn = None
        try:
            shutil.copy2(predictor_path, temp_db)
            conn = self._connect_db(temp_db); cursor = conn.cursor()
            for user_text, url, hits in cursor.execute("SELECT user_text, url, number_of_hits FROM network_action_predictor ORDER BY number_of_hits DESC"):
                self.add_artifact(browser_name, 'Network Predictor', {
                    'URL': url, 
                    'Title': user_text, 
                    'Value': f"Hits: {hits}", 
                    'Status': 'Predicted',
                    'Deep': 'Yes',
                    'Web Permissions': self.get_permissions_for_url(url),
                    'Session': 'Standard'
                })
        except Exception as e:
            self.log_event("Extraction Error", f"{browser_name} Network Predictor: {str(e)}")
        finally:
            if conn: conn.close()

    def run_scan(self, deep_scan=False, scan_credentials=False):
        """Run a scan and return a fresh batch of results.
        
        Note: self.results is cleared each call. The GUI accumulates results
        across multiple scans in its own analysis_results list.
        """
        self.log_event("Scan Started", f"Deep Scan: {deep_scan}, Credentials: {scan_credentials}")
        if not self.forensic_mode:
            self._cleanup_temp()
        else:
            if not os.path.exists(self.temp_dir):
                os.makedirs(self.temp_dir, exist_ok=True)
        
        self.results = []
        self.load_all_permissions()
        for browser in self.browsers:
            name, path = browser['name'], browser['path']
            self.log_event("Processing Browser", f"Extracting data from {name}")
            
            if name == 'Firefox':
                if os.path.exists(path):
                    self.process_firefox_history(path)
                    if deep_scan:
                        self.process_firefox_extensions(name, path)
                    if scan_credentials:
                        self.log_event("Info", f"Firefox credential decryption is not yet supported. Skipping {name} credentials.")
                continue
            
            if name == 'Internet Explorer':
                self.process_ie_typed_urls()
                continue

            profile_path = os.path.join(path, "Default")
            if not os.path.exists(profile_path) and os.path.exists(os.path.join(path, "History")): profile_path = path
            local_state = os.path.join(os.path.dirname(profile_path) if "Default" in profile_path else path, "Local State")
            history_db = os.path.join(profile_path, "History")
            if os.path.exists(history_db):
                self.process_history(name, history_db, deep_scan)
                if deep_scan:
                    self.process_downloads(name, history_db)
                    self.process_search_terms(name, history_db)
            if deep_scan:
                bookmarks_file = os.path.join(profile_path, "Bookmarks")
                if os.path.exists(bookmarks_file): self.process_bookmarks(name, bookmarks_file)
                cookies_db = os.path.join(profile_path, "Network", "Cookies")
                if not os.path.exists(cookies_db): cookies_db = os.path.join(profile_path, "Cookies")
                if os.path.exists(cookies_db) and os.path.exists(local_state): self.process_cookies(name, cookies_db, local_state)
                web_data_db = os.path.join(profile_path, "Web Data")
                if os.path.exists(web_data_db): self.process_autofills(name, web_data_db)
                extensions_dir = os.path.join(profile_path, "Extensions")
                if os.path.exists(extensions_dir): self.process_extensions(name, extensions_dir)
                top_sites_db = os.path.join(profile_path, "Top Sites")
                if os.path.exists(top_sites_db): self.process_top_sites(name, top_sites_db)
                predictor_db = os.path.join(profile_path, "Network Action Predictor")
                if os.path.exists(predictor_db): self.process_network_predictor(name, predictor_db)
            if scan_credentials:
                login_db = os.path.join(profile_path, "Login Data")
                if os.path.exists(login_db) and os.path.exists(local_state): self.process_credentials(name, login_db, local_state)
        
        if self.forensic_mode:
            self._cleanup_temp(recreate=False)
        
        self.log_event("Scan Completed", f"Total artifacts found: {len(self.results)}")
        return self.results

    def generate_report(self, output_path, results=None):
        if results is None: results = self.results
        self.log_event("Export Started", f"Generating XLSX report: {os.path.basename(output_path)}")
        workbook = xlsxwriter.Workbook(output_path, {'strings_to_urls': False})
        header_fmt = workbook.add_format({'bold': True, 'bg_color': '#FF8C00', 'font_color': '#FFFFFF'})
        match_fmt = workbook.add_format({'bg_color': '#FFCCCC', 'font_color': '#FF0000'})
        
        ws_summary = workbook.add_worksheet("Case Summary")
        ws_summary.write(0, 0, "Case Number", header_fmt); ws_summary.write(0, 1, self.case_details.get("Case Number", "N/A"))
        ws_summary.write(1, 0, "Evidence ID", header_fmt); ws_summary.write(1, 1, self.case_details.get("Evidence ID", "N/A"))
        ws_summary.write(2, 0, "Examiner", header_fmt); ws_summary.write(2, 1, self.case_details.get("Examiner Name", "N/A"))
        ws_summary.write(3, 0, "Purpose", header_fmt); ws_summary.write(3, 1, self.case_details.get("Purpose of Investigation", "N/A"))
        ws_summary.write(4, 0, "Detected Browsers", header_fmt); ws_summary.write(4, 1, ", ".join([b['name'] for b in self.browsers]))
        ws_summary.write(5, 0, "Total Artifacts", header_fmt); ws_summary.write(5, 1, len(results))
        ws_summary.write(6, 0, "Watchlist", header_fmt); ws_summary.write(6, 1, ", ".join(self.watchlist))
        ws_summary.write(7, 0, "Forensic Mode", header_fmt); ws_summary.write(7, 1, "Enabled" if self.forensic_mode else "Disabled")

        def create_sheet(name, artifact_types, headers, data_keys):
            ws = workbook.add_worksheet(name)
            for col, h in enumerate(headers): ws.write(0, col, h, header_fmt)
            row = 1
            for item in results:
                if item.artifact_type in artifact_types:
                    d = item.data
                    row_data = [item.browser_name] + [str(d.get(k, '')) for k in data_keys]
                    fmt = match_fmt if d.get('Watchlist Match') == 'Yes' else None
                    for col, val in enumerate(row_data):
                        ws.write(row, col, val, fmt)
                    row += 1

        create_sheet("History", ["History"], ["Browser", "Timestamp", "URL", "Title", "Visit Count", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["Timestamp", "URL", "Title", "Visit Count", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        create_sheet("Downloads", ["Download"], ["Browser", "Timestamp", "URL", "File Name", "Local Path", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["Timestamp", "URL", "Title", "Value", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        create_sheet("Bookmarks", ["Bookmark"], ["Browser", "URL", "Title", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["URL", "Title", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        create_sheet("Cookies", ["Cookie"], ["Browser", "Host", "Name", "Value", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["URL", "Title", "Value", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        create_sheet("Search Terms", ["Search Term"], ["Browser", "URL", "Term", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["URL", "Value", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        create_sheet("Autofills", ["Autofill"], ["Browser", "Name", "Value", "Deep", "Session", "Location", "Watchlist Match"], ["Title", "Value", "Deep", "Session", "Location", "Watchlist Match"])
        create_sheet("Credentials", ["Credential"], ["Browser", "URL", "Username", "Password", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["URL", "Username", "Password", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        create_sheet("Deleted History", ["Deleted History"], ["Browser", "URL", "Status", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["URL", "Status", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        create_sheet("Web Permissions", ["Web Permission"], ["Browser", "URL", "Permissions", "Status", "Deep", "Session", "Location", "Watchlist Match"], ["URL", "Value", "Status", "Deep", "Session", "Location", "Watchlist Match"])
        create_sheet("Extensions", ["Extension"], ["Browser", "ID", "Name", "Details", "Status", "Deep", "Session", "Location", "Watchlist Match"], ["URL", "Title", "Value", "Status", "Deep", "Session", "Location", "Watchlist Match"])
        create_sheet("Top Sites", ["Top Site"], ["Browser", "URL", "Title", "Details", "Status", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["URL", "Title", "Value", "Status", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        create_sheet("Network Predictors", ["Network Predictor"], ["Browser", "URL", "User Text", "Hits", "Status", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["URL", "Title", "Value", "Status", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        
        ws_timeline = workbook.add_worksheet("Investigator Timeline")
        timeline_headers = ["Browser", "Artifact Type", "URL", "Title", "Timestamp", "Value", "Deep", "Location", "Watchlist Match"]
        for col, h in enumerate(timeline_headers): ws_timeline.write(0, col, h, header_fmt)
        timeline_items = []
        for item in results:
            ts = item.data.get('Timestamp')
            if ts and str(ts) not in ["Unknown", "N/A"]: timeline_items.append((str(ts), item))
        timeline_items.sort(key=lambda x: x[0], reverse=True)
        for row, (ts, item) in enumerate(timeline_items, 1):
            d = item.data
            val = d.get('Value') or d.get('Term') or d.get('File Name') or ""
            row_data = [item.browser_name, item.artifact_type, d.get('URL', ''), d.get('Title', ''), ts, val, d.get('Deep', ''), d.get('Location', ''), d.get('Watchlist Match', 'No')]
            fmt = match_fmt if str(d.get('Watchlist Match')).startswith('Yes') else None
            ws_timeline.write_row(row, 0, [str(v) if v is not None else "" for v in row_data], fmt)
        
        ws_log = workbook.add_worksheet("Activity Logs")
        log_headers = ["Step", "Timestamp", "Action", "Details"]
        for col, h in enumerate(log_headers): ws_log.write(0, col, h, header_fmt)
        for row, entry in enumerate(self.activity_log, 1):
            ws_log.write_row(row, 0, [entry["Step"], entry["Timestamp"], entry["Action"], entry["Details"]])
            
        workbook.close()
        self.log_event("Export Completed", "XLSX report generated successfully.")

    def generate_jsonl(self, output_path, results=None):
        if results is None: results = self.results
        self.log_event("Export Started", f"Generating JSONL report: {os.path.basename(output_path)}")
        with open(output_path, 'w', encoding='utf-8') as f:
            for item in results:
                record = {
                    "case_number": self.case_details.get("Case Number", "N/A"),
                    "evidence_id": self.case_details.get("Evidence ID", "N/A"),
                    "examiner": self.case_details.get("Examiner Name", "N/A"),
                    "purpose": self.case_details.get("Purpose of Investigation", "N/A"),
                    "browser": item.browser_name, 
                    "type": item.artifact_type, 
                    **item.data
                }
                if "Timestamp" in record and isinstance(record["Timestamp"], datetime.datetime):
                    record["Timestamp"] = record["Timestamp"].isoformat()
                f.write(json.dumps(record) + "\n")
        self.log_event("Export Completed", "JSONL report generated successfully.")

    def generate_sqlite(self, output_path, results=None):
        if results is None: results = self.results
        self.log_event("Export Started", f"Generating SQLite report: {os.path.basename(output_path)}")
        conn = sqlite3.connect(output_path); cursor = conn.cursor()
        
        # Create and populate Case Metadata table
        cursor.execute("CREATE TABLE case_metadata (key TEXT, value TEXT)")
        for k in ["Case Number", "Evidence ID", "Examiner Name", "Purpose of Investigation"]:
            cursor.execute("INSERT INTO case_metadata (key, value) VALUES (?, ?)", (k, self.case_details.get(k, "N/A")))
            
        tables = {
            "history": (["browser", "timestamp", "url", "title", "visit_count", "deep", "web_permissions", "session", "location", "watchlist_match"], ["Timestamp", "URL", "Title", "Visit Count", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"]), 
            "download": (["browser", "timestamp", "url", "file_name", "local_path", "deep", "web_permissions", "session", "location", "watchlist_match"], ["Timestamp", "URL", "Title", "Value", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"]), 
            "bookmark": (["browser", "url", "title", "deep", "web_permissions", "session", "location", "watchlist_match"], ["URL", "Title", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"]), 
            "cookie": (["browser", "host", "name", "value", "deep", "web_permissions", "session", "location", "watchlist_match"], ["URL", "Title", "Value", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"]), 
            "search_term": (["browser", "url", "term", "deep", "web_permissions", "session", "location", "watchlist_match"], ["URL", "Value", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"]), 
            "autofill": (["browser", "name", "value", "deep", "session", "location", "watchlist_match"], ["Title", "Value", "Deep", "Session", "Location", "Watchlist Match"]), 
            "credential": (["browser", "url", "username", "password", "deep", "web_permissions", "session", "location", "watchlist_match"], ["URL", "Username", "Password", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"]), 
            "deleted_history": (["browser", "url", "status", "deep", "web_permissions", "session", "location", "watchlist_match"], ["URL", "Status", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"]),
            "web_permission": (["browser", "url", "permissions", "status", "deep", "session", "location", "watchlist_match"], ["URL", "Value", "Status", "Deep", "Session", "Location", "Watchlist Match"]),
            "extension": (["browser", "ext_id", "name", "details", "status", "deep", "session", "location", "watchlist_match"], ["URL", "Title", "Value", "Status", "Deep", "Session", "Location", "Watchlist Match"]),
            "top_site": (["browser", "url", "title", "details", "status", "deep", "web_permissions", "session", "location", "watchlist_match"], ["URL", "Title", "Value", "Status", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"]),
            "network_predictor": (["browser", "url", "user_text", "hits", "status", "deep", "web_permissions", "session", "location", "watchlist_match"], ["URL", "Title", "Value", "Status", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"]),
            "activity_logs": (["step", "timestamp", "action", "details"], ["Step", "Timestamp", "Action", "Details"])
        }
        for table_name, (cols, _) in tables.items(): cursor.execute(f"CREATE TABLE {table_name} (id INTEGER PRIMARY KEY AUTOINCREMENT, {', '.join([c + ' TEXT' for c in cols])})")
        
        for item in results:
            cat = item.artifact_type.lower().replace(" ", "_")
            if cat in tables:
                cols, keys = tables[cat]
                vals = [item.browser_name] + [str(item.data.get(k, '')) for k in keys]
                cursor.execute(f"INSERT INTO {cat} ({', '.join(cols)}) VALUES ({', '.join(['?' for _ in vals])})", vals)
        
        for entry in self.activity_log:
            cursor.execute("INSERT INTO activity_logs (step, timestamp, action, details) VALUES (?, ?, ?, ?)", (entry["Step"], entry["Timestamp"], entry["Action"], entry["Details"]))
            
        cursor.execute("CREATE TABLE investigator_timeline (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, browser TEXT, type TEXT, url TEXT, title TEXT, value TEXT, location TEXT, watchlist_match TEXT)")
        timeline_items = []
        for item in results:
            ts = item.data.get('Timestamp')
            if ts and str(ts) not in ["Unknown", "N/A"]: timeline_items.append((str(ts), item))
        timeline_items.sort(key=lambda x: x[0], reverse=True)
        for ts, item in timeline_items:
            d = item.data
            val = d.get('Value') or d.get('Term') or d.get('File Name') or ""
            cursor.execute("INSERT INTO investigator_timeline (timestamp, browser, type, url, title, value, location, watchlist_match) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", 
                           (ts, item.browser_name, item.artifact_type, str(d.get('URL', '')), str(d.get('Title', '')), str(val), str(d.get('Location', '')), str(d.get('Watchlist Match', 'No'))))

        conn.commit(); conn.close()
        self.log_event("Export Completed", "SQLite report generated successfully.")

    def generate_html(self, output_path, results=None):
        if results is None: results = self.results
        self.log_event("Export Started", f"Generating HTML report: {os.path.basename(output_path)}")
        
        css = """
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; color: #333; display: flex; height: 100vh; overflow: hidden; }
            #sidebar { width: 270px; min-width: 270px; flex-shrink: 0; background-color: #1a1a2e; color: white; padding: 25px 20px; overflow-y: auto; box-shadow: 3px 0 10px rgba(0,0,0,0.3); }
            #sidebar h3 { color: #FF8C00; font-size: 18px; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 2px solid #FF8C00; letter-spacing: 1px; text-transform: uppercase; }
            #sidebar a { display: block; color: #ffffff; text-decoration: none; padding: 10px 14px; margin-bottom: 4px; border-radius: 6px; font-size: 14px; font-weight: 500; transition: all 0.2s ease; border-bottom: none; }
            #sidebar a:hover { background-color: #FF8C00; color: #ffffff; transform: translateX(4px); }
            #content { flex-grow: 1; padding: 40px; overflow-y: auto; background-color: #f9f9f9; }
            h1, h2 { color: #FF8C00; border-bottom: 2px solid #FF8C00; padding-bottom: 10px; margin-top: 40px; }
            .table-container { overflow-x: auto; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 5px; background: white; }
            table { border-collapse: collapse; width: 100%; min-width: 1000px; font-size: 13px; table-layout: fixed; }
            th, td { border: 1px solid #ddd; padding: 10px; text-align: left; word-break: break-all; word-wrap: break-word; }
            th { background-color: #FF8C00; color: white; position: sticky; top: 0; }
            tr:nth-child(even) { background-color: #f8f9fa; }
            tr:hover { background-color: #e9ecef; }
            .highlight { background-color: #FFCCCC !important; color: #FF0000; font-weight: bold; }
            .summary-table { width: 100%; min-width: auto; table-layout: auto; }
            .summary-table th { width: 30%; background-color: #34495e; }
        </style>
        """
        
        nav_links = '<div id="sidebar"><h3>🔍 BrosFros Navigation</h3><a href="#summary">📋 Case Summary</a>'
        sections = ""
        
        sections += "<h2 id='summary'>Case Summary</h2><div class='table-container'><table class='summary-table'>"
        sections += f"<tr><th>Case Number</th><td>{self.case_details.get('Case Number', 'N/A')}</td></tr>"
        sections += f"<tr><th>Evidence ID</th><td>{self.case_details.get('Evidence ID', 'N/A')}</td></tr>"
        sections += f"<tr><th>Examiner</th><td>{self.case_details.get('Examiner Name', 'N/A')}</td></tr>"
        sections += f"<tr><th>Purpose</th><td>{self.case_details.get('Purpose of Investigation', 'N/A')}</td></tr>"
        sections += f"<tr><th>Total Artifacts</th><td>{len(results)}</td></tr>"
        sections += f"<tr><th>Export Time</th><td>{datetime.datetime.now().isoformat()}</td></tr>"
        sections += "</table></div>"
        
        def add_html_section(title, anchor, artifact_types, headers, data_keys):
            nonlocal sections, nav_links
            items = [item for item in results if item.artifact_type in artifact_types]
            if not items: return
            
            nav_links += f"<a href='#{anchor}'>{title} ({len(items)})</a>"
            
            sections += f"<h2 id='{anchor}'>{title} ({len(items)})</h2><div class='table-container'><table>"
            sections += "<tr>" + "".join(f"<th>{h}</th>" for h in headers) + "</tr>"
            
            for item in items:
                d = item.data
                row_data = [item.browser_name] + [str(d.get(k, '')) for k in data_keys]
                match = str(d.get('Watchlist Match', 'No'))
                row_class = " class='highlight'" if match.startswith('Yes') else ""
                sections += f"<tr{row_class}>" + "".join(f"<td>{val}</td>" for val in row_data) + "</tr>"
            sections += "</table></div>"

        add_html_section("🔍 History", "history", ["History"], ["Browser", "Timestamp", "URL", "Title", "Visit Count", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["Timestamp", "URL", "Title", "Visit Count", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        add_html_section("📥 Downloads", "downloads", ["Download"], ["Browser", "Timestamp", "URL", "File Name", "Local Path", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["Timestamp", "URL", "Title", "Value", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        add_html_section("🔖 Bookmarks", "bookmarks", ["Bookmark"], ["Browser", "URL", "Title", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["URL", "Title", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        add_html_section("🍪 Cookies", "cookies", ["Cookie"], ["Browser", "Host", "Name", "Value", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["URL", "Title", "Value", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        add_html_section("🔎 Search Terms", "search_terms", ["Search Term"], ["Browser", "URL", "Term", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["URL", "Value", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        add_html_section("📝 Autofills", "autofills", ["Autofill"], ["Browser", "Name", "Value", "Deep", "Session", "Location", "Watchlist Match"], ["Title", "Value", "Deep", "Session", "Location", "Watchlist Match"])
        add_html_section("🔑 Credentials", "credentials", ["Credential"], ["Browser", "URL", "Username", "Password", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["URL", "Username", "Password", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        add_html_section("🗑️ Deleted History", "deleted_history", ["Deleted History"], ["Browser", "URL", "Status", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["URL", "Status", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        add_html_section("🛡️ Web Permissions", "web_permissions", ["Web Permission"], ["Browser", "URL", "Permissions", "Status", "Deep", "Session", "Location", "Watchlist Match"], ["URL", "Value", "Status", "Deep", "Session", "Location", "Watchlist Match"])
        add_html_section("🧩 Extensions", "extensions", ["Extension"], ["Browser", "ID", "Name", "Details", "Status", "Deep", "Session", "Location", "Watchlist Match"], ["URL", "Title", "Value", "Status", "Deep", "Session", "Location", "Watchlist Match"])
        add_html_section("⭐ Top Sites", "top_sites", ["Top Site"], ["Browser", "URL", "Title", "Details", "Status", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["URL", "Title", "Value", "Status", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])
        add_html_section("🌐 Network Predictors", "network_predictors", ["Network Predictor"], ["Browser", "URL", "User Text", "Hits", "Status", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"], ["URL", "Title", "Value", "Status", "Deep", "Web Permissions", "Session", "Location", "Watchlist Match"])

        timeline_items = []
        for item in results:
            ts = item.data.get('Timestamp')
            if ts and str(ts) not in ["Unknown", "N/A"]: timeline_items.append((str(ts), item))
        
        if timeline_items:
            nav_links += f"<a href='#timeline'>🕒 Investigator Timeline ({len(timeline_items)})</a>"
            sections += f"<h2 id='timeline'>Investigator Timeline ({len(timeline_items)})</h2><div class='table-container'><table>"
            sections += "<tr><th>Timestamp</th><th>Browser</th><th>Type</th><th>URL</th><th>Title</th><th>Value</th><th>Location</th><th>Watchlist Match</th></tr>"
            timeline_items.sort(key=lambda x: x[0], reverse=True)
            for ts, item in timeline_items:
                d = item.data
                val = d.get('Value') or d.get('Term') or d.get('File Name') or ""
                match = str(d.get('Watchlist Match', 'No'))
                row_class = " class='highlight'" if match.startswith('Yes') else ""
                sections += f"<tr{row_class}><td>{ts}</td><td>{item.browser_name}</td><td>{item.artifact_type}</td><td>{d.get('URL', '')}</td><td>{d.get('Title', '')}</td><td>{val}</td><td>{d.get('Location', '')}</td><td>{match}</td></tr>"
            sections += "</table></div>"

        nav_links += "</div>"
        
        html_content = f"<html><head><title>BrosFros Report</title><meta charset='utf-8'>{css}</head><body>"
        html_content += nav_links
        html_content += f"<div id='content'><h1>BrosFros Forensic Report</h1>{sections}</div>"
        html_content += "</body></html>"
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        self.log_event("Export Completed", "HTML report generated successfully.")

    def generate_pdf_report(self, output_path, results=None):
        if results is None: results = self.results
        self.log_event("Export Started", f"Generating Comprehensive PDF report: {os.path.basename(output_path)}")
        doc = SimpleDocTemplate(output_path, pagesize=landscape(letter), rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=18)
        elements = []
        styles = getSampleStyleSheet()
        title_style = styles['Title']
        h2_style = styles['Heading2']
        normal_style = styles['Normal']
        
        elements.append(Paragraph("BrosFros Forensic Report", title_style))
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(f"<b>Case Number:</b> {self.case_details.get('Case Number', 'N/A')}", normal_style))
        elements.append(Paragraph(f"<b>Evidence ID:</b> {self.case_details.get('Evidence ID', 'N/A')}", normal_style))
        elements.append(Paragraph(f"<b>Examiner:</b> {self.case_details.get('Examiner Name', 'N/A')}", normal_style))
        elements.append(Paragraph(f"<b>Total Artifacts:</b> {len(results)}", normal_style))
        elements.append(Paragraph(f"<b>Export Time:</b> {datetime.datetime.now().isoformat()}", normal_style))
        elements.append(Spacer(1, 30))
        
        def create_pdf_table(title, artifact_types, headers, data_keys):
            items = [item for item in results if item.artifact_type in artifact_types]
            if not items: return
            
            elements.append(Paragraph(f"{title} ({len(items)})", h2_style))
            elements.append(Spacer(1, 10))
            
            data = [headers]
            for item in items:
                d = item.data
                row_data = [str(item.browser_name)]
                for k in data_keys:
                    val = str(d.get(k, ''))
                    if len(val) > 80: val = val[:77] + "..."
                    row_data.append(val)
                match = str(d.get('Watchlist Match', 'No'))
                row_data.append(match)
                data.append(row_data)
                
            t = Table(data, repeatRows=1)
            style_cmds = [
                ('BACKGROUND', (0,0), (-1,0), colors.darkorange),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,0), 6),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,1), (-1,-1), 4),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey)
            ]
            
            for i, item in enumerate(items, 1):
                if str(item.data.get('Watchlist Match', 'No')).startswith('Yes'):
                    style_cmds.append(('BACKGROUND', (0, i), (-1, i), colors.mistyrose))
                    style_cmds.append(('TEXTCOLOR', (0, i), (-1, i), colors.red))
            
            t.setStyle(TableStyle(style_cmds))
            elements.append(t)
            elements.append(Spacer(1, 20))

        create_pdf_table("History", ["History"], ["Browser", "Timestamp", "URL", "Title", "Match"], ["Timestamp", "URL", "Title"])
        create_pdf_table("Downloads", ["Download"], ["Browser", "Timestamp", "URL", "File", "Match"], ["Timestamp", "URL", "Title"])
        create_pdf_table("Bookmarks", ["Bookmark"], ["Browser", "URL", "Title", "Match"], ["URL", "Title"])
        create_pdf_table("Cookies", ["Cookie"], ["Browser", "URL", "Title", "Value", "Match"], ["URL", "Title", "Value"])
        create_pdf_table("Search Terms", ["Search Term"], ["Browser", "URL", "Term", "Match"], ["URL", "Value"])
        create_pdf_table("Autofills", ["Autofill"], ["Browser", "Name", "Value", "Match"], ["Title", "Value"])
        create_pdf_table("Credentials", ["Credential"], ["Browser", "URL", "Username", "Password", "Match"], ["URL", "Username", "Password"])
        create_pdf_table("Deleted History", ["Deleted History"], ["Browser", "URL", "Status", "Match"], ["URL", "Status"])
        create_pdf_table("Web Permissions", ["Web Permission"], ["Browser", "URL", "Permissions", "Status", "Match"], ["URL", "Value", "Status"])
        create_pdf_table("Extensions", ["Extension"], ["Browser", "URL", "Name", "Details", "Status", "Match"], ["URL", "Title", "Value", "Status"])
        create_pdf_table("Top Sites", ["Top Site"], ["Browser", "URL", "Title", "Status", "Match"], ["URL", "Title", "Status"])
        create_pdf_table("Network Predictors", ["Network Predictor"], ["Browser", "URL", "User Text", "Status", "Match"], ["URL", "Title", "Status"])
        
        timeline_items = []
        for item in results:
            ts = item.data.get('Timestamp')
            if ts and str(ts) not in ["Unknown", "N/A"]: timeline_items.append((str(ts), item))
        
        if timeline_items:
            elements.append(Paragraph(f"Investigator Timeline ({len(timeline_items)})", h2_style))
            elements.append(Spacer(1, 10))
            timeline_items.sort(key=lambda x: x[0], reverse=True)
            data = [["Timestamp", "Browser", "Type", "URL", "Value", "Match"]]
            style_cmds = [
                ('BACKGROUND', (0,0), (-1,0), colors.darkorange),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,0), 6),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,1), (-1,-1), 4),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey)
            ]
            for i, (ts, item) in enumerate(timeline_items, 1):
                d = item.data
                val = d.get('Value') or d.get('Term') or d.get('File Name') or ""
                url = d.get('URL', '')
                if len(url) > 60: url = url[:57] + "..."
                if len(val) > 60: val = val[:57] + "..."
                match = str(d.get('Watchlist Match', 'No'))
                data.append([ts, item.browser_name, item.artifact_type, url, val, match])
                if match.startswith('Yes'):
                    style_cmds.append(('BACKGROUND', (0, i), (-1, i), colors.mistyrose))
                    style_cmds.append(('TEXTCOLOR', (0, i), (-1, i), colors.red))
            
            t = Table(data, repeatRows=1)
            t.setStyle(TableStyle(style_cmds))
            elements.append(t)
            
        doc.build(elements)
        self.log_event("Export Completed", "Comprehensive PDF report generated successfully.")

    def generate_activity_log_report(self, output_path, results=None):
        self.log_event("Export Started", f"Generating Activity Log XLSX report: {os.path.basename(output_path)}")
        workbook = xlsxwriter.Workbook(output_path)
        ws_log = workbook.add_worksheet("Activity Logs")
        header_fmt = workbook.add_format({'bold': True, 'bg_color': '#FF8C00', 'font_color': '#FFFFFF'})
        log_headers = ["Step", "Timestamp", "Action", "Details"]
        for col, h in enumerate(log_headers): ws_log.write(0, col, h, header_fmt)
        for row, entry in enumerate(self.activity_log, 1):
            ws_log.write_row(row, 0, [entry["Step"], entry["Timestamp"], entry["Action"], entry["Details"]])
        workbook.close()
        self.log_event("Export Completed", "Activity Log report generated successfully.")

    def generate_full_zip(self, output_path, password, results=None):
        self.log_event("Export Started", f"Generating Encrypted 7z archive: {os.path.basename(output_path)}")
        
        os.makedirs(self.temp_dir, exist_ok=True)
        
        files_to_zip = {
            "BrosFros_Report.xlsx": self.generate_report,
            "BrosFros_Report.jsonl": self.generate_jsonl,
            "BrosFros_Report.sqlite": self.generate_sqlite,
            "BrosFros_Report.pdf": self.generate_pdf_report,
            "BrosFros_Report.html": self.generate_html,
            "BrosFros_ActivityLog.xlsx": self.generate_activity_log_report,
            "BrosFros_Credentials.pdf": lambda path, res: self.generate_pdf_report(path, results=[r for r in (res or self.results) if r.artifact_type == "Credential"])
        }
        
        generated_files = {}
        for filename, func in files_to_zip.items():
            filepath = os.path.join(self.temp_dir, filename)
            try:
                func(filepath, results)
                generated_files[filename] = filepath
            except Exception as e:
                self.log_event("Export Error", f"Failed to generate {filename} for zip: {str(e)}")

        # Create Integrity Hashes file
        integrity_file = os.path.join(self.temp_dir, "Integrity_Hashes.txt")
        with open(integrity_file, "w", encoding="utf-8") as f:
            f.write(f"BrosFros Forensic Suite\nCase: {self.case_details.get('Case Number', 'N/A')}\nExport Time: {datetime.datetime.now().isoformat()}\n\n")
            f.write("--- EXPORTED FILE INTEGRITY HASHES (SHA-256) ---\n\n")
            for filename, filepath in generated_files.items():
                sha256 = hashlib.sha256()
                with open(filepath, "rb") as hf:
                    for chunk in iter(lambda: hf.read(4096), b""):
                        sha256.update(chunk)
                f.write(f"{sha256.hexdigest()}  {filename}\n")
            
            if self.source_hashes:
                f.write("\n--- SOURCE EVIDENCE HASHES (CHAIN OF CUSTODY) ---\n\n")
                for path, h in self.source_hashes.items():
                    f.write(f"{h}  | Source: {path}\n")
        
        generated_files["Integrity_Hashes.txt"] = integrity_file

        with py7zr.SevenZipFile(output_path, 'w', password=password) as archive:
            for filename, filepath in generated_files.items():
                archive.write(filepath, arcname=filename)
            
        for filepath in generated_files.values():
            if os.path.exists(filepath):
                os.remove(filepath)
                
        self.log_event("Export Completed", "Encrypted 7z archive generated successfully with all formats and hashes.")

    def generate_manifest(self, report_path):
        manifest_path = f"{report_path}.manifest.json"
        
        # Hash the report file
        md5, sha256 = hashlib.md5(), hashlib.sha256()
        try:
            with open(report_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5.update(chunk); sha256.update(chunk)
            report_hashes = {"MD5": md5.hexdigest(), "SHA256": sha256.hexdigest()}
        except Exception:
            report_hashes = {}

        manifest_data = {
            "case_details": self.case_details,
            "export_time": datetime.datetime.now().isoformat(),
            "report_file": os.path.basename(report_path),
            "report_hashes": report_hashes,
            "source_evidence_hashes": self.source_hashes
        }
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=4)
            
        self.log_event("Manifest Generated", f"Manifest saved at {manifest_path}")
        return manifest_path
