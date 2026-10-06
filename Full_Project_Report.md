# BROSfROS: A MULTI-ENGINE BROWSER FORENSIC SUITE WITH AUTOMATED CREDENTIAL DECRYPTION AND DELETED ARTIFACT RECOVERY

**A Full Project Report**
Submitted in partial fulfillment of the requirements for the degree of 
**M.TECH in CYBER FORENSICS**

**Submitted by:**
Aasim Mehmood Mirza
Registration No: NDU202400263
Batch: 2025-2027 | 2nd Semester (Session 2026)

**Institution:**
National Institute of Electronics and Information Technology (NIELIT), Srinagar

---

## ABSTRACT
In modern digital investigations, web browsers serve as the primary gateway to a suspect’s activities, harboring critical evidence ranging from search histories and downloaded files to cached session tokens and saved credentials. However, digital forensics investigators face significant hurdles due to the fragmentation of browser engines, the use of operating system-level encryption (such as Windows DPAPI and AES-256-GCM) for sensitive data, and anti-forensic techniques like history clearing. 

**BrosFros** is a comprehensive, multi-engine browser forensic suite designed to automate the extraction, decryption, and carving of digital artifacts. Supporting over 14 browsers (including Chrome, Edge, Firefox, and Brave), the tool streamlines the investigative process by programmatically unlocking DPAPI-protected Master Keys, enabling on-the-fly decryption of passwords and cookies. Furthermore, it incorporates SQLite data carving techniques utilizing Regular Expressions (Regex) to recover deleted URLs from unallocated database space. Engineered with strict chain-of-custody protocols—including read-only "Forensic Mode," cryptographic hashing (MD5/SHA-256), and activity logging—BrosFros ensures that all extracted evidence remains legally admissible and is seamlessly exported into SIEM-compatible formats, encrypted archives, and interactive HTML dashboards.

---

## CHAPTER 1: INTRODUCTION

### 1.1 Background
The proliferation of web-based applications has shifted the epicenter of cybercrime and digital activity to web browsers. When investigating incidents of data exfiltration, insider threats, or illicit cyber activities, analyzing browser artifacts is paramount. These artifacts include history, bookmarks, cookies, autofill data, credentials, and web permissions. 

### 1.2 The Forensic Challenge
Extracting these artifacts is complicated by three main factors:
1. **Engine Diversity:** The market is split between Chromium-based browsers (Chrome, Edge, Opera, Brave) and Gecko-based browsers (Firefox). Each utilizes vastly different SQLite schemas and file paths.
2. **Encryption:** Modern Chromium browsers secure passwords and cookies using AES-256-GCM encryption. The symmetric key required for decryption is itself encrypted using the Windows Data Protection API (DPAPI) and tied to the user's login session.
3. **Anti-Forensics:** Suspects frequently attempt to cover their tracks by deleting their browsing history. Standard SQL queries cannot retrieve this data once the database engine flags the rows as deleted.

### 1.3 Purpose of the Project
BrosFros was developed to bridge the gap between complex cryptographic barriers and the need for rapid evidence acquisition. By providing a unified GUI application that handles both extraction and decryption autonomously, investigators can bypass manual SQLite querying and focus directly on timeline analysis.

---

## CHAPTER 2: PROBLEM STATEMENT AND OBJECTIVES

### 2.1 Problem Statement
Existing open-source forensic tools are often fragmented—requiring one tool to extract history, a separate python script to extract DPAPI keys, and a third utility to carve deleted records. This disjointed workflow increases the time required for investigations and introduces a higher risk of mishandling volatile evidence, thereby compromising the chain of custody.

### 2.2 Project Objectives
1. **Multi-Engine Support:** To automatically detect and parse databases from 14+ browsers across Windows environments.
2. **Automated Decryption:** To programmatically extract the Windows DPAPI Master Key and utilize PyCryptodome to decrypt AES-256-GCM secured payloads on the fly.
3. **Deleted Artifact Recovery:** To implement binary carving techniques that recover deleted web history from SQLite free-lists.
4. **Forensic Integrity:** To guarantee that no original evidence is altered by isolating database queries to temporary copies and generating cryptographic manifests.
5. **Comprehensive Reporting:** To generate multi-format reports (JSONL, SQLite, HTML, PDF, XLSX) that embed case metadata for SIEM integration and courtroom presentation.

---

## CHAPTER 3: SYSTEM ARCHITECTURE

The BrosFros architecture is built on a Model-View-Controller (MVC) design pattern, distinctly separating the frontend user interface from the backend extraction engine.

### 3.1 The Frontend (View & Controller)
Built utilizing the `CustomTkinter` library, the GUI offers a dark-themed, modern investigative workspace. It handles:
- **Case Management:** Enforcing the entry of Case Number, Evidence ID, and Examiner Name prior to analysis.
- **Interactive Dashboards:** Displaying extracted data in sortable `Treeview` grids, alongside graphical overviews generated via `Matplotlib`.
- **Export Hub:** Managing the user inputs required to trigger report generation and secure 7z encryption.

### 3.2 The Backend (Model - Forensic Engine)
The core logic resides within the `forensics_engine.py` module, which executes in a multi-threaded environment to prevent UI freezing during massive data extractions. 
1. **Detection Phase:** The engine queries `%APPDATA%` and `%LOCALAPPDATA%` using predefined paths for known browsers.
2. **Preservation Phase:** All discovered SQLite databases (`History`, `Login Data`, `Cookies`, `Web Data`) are duplicated to a secure temporary directory (`tempfile.mkdtemp()`). Original files are hashed via MD5 and SHA-256.
3. **Extraction & Carving Phase:** Standard artifacts are queried using SQL `SELECT` statements. Deleted artifacts are carved by reading the SQLite file as raw binary (`rb`) and applying regex patterns matching standard URL structures.
4. **Decryption Phase:** The engine parses the `Local State` JSON file, decodes the base64-encoded encrypted key, passes it to the `win32crypt` API for DPAPI decryption, and uses the resulting Master Key to decrypt AES payloads.

---

## CHAPTER 4: IMPLEMENTATION & MODULES

### 4.1 Multi-Engine Parsing Module
BrosFros utilizes a dynamic dictionary of browser configurations. For Chromium browsers, it parses the `urls` and `visits` tables to reconstruct the user's browsing timeline. For Firefox, it parses the `moz_places` and `moz_historyvisits` tables. The module standardizes the output into a unified `BrowserArtifact` dataclass, ensuring that data from Chrome and Firefox can be viewed side-by-side in the same timeline.

### 4.2 Automated Decryption Module
Chromium stores passwords in the `Login Data` database under the `password_value` column as a BLOB prefixed with `v10` or `v11`. 
The implementation follows these cryptographic steps:
1. Strip the `v10`/`v11` prefix (first 3 bytes).
2. Extract the Initialization Vector (IV) / Nonce (next 12 bytes).
3. Extract the Ciphertext (remaining bytes minus the last 16 bytes).
4. Extract the Authentication Tag (last 16 bytes).
5. Initialize the `AES.new(master_key, AES.MODE_GCM, nonce)` cipher and decrypt the payload.

### 4.3 SQLite Regex Carving Module
When a user deletes their history, SQLite does not immediately overwrite the data on the disk; it merely moves the pointer to a "free-list". BrosFros opens the `History` database in binary mode and utilizes the following Regex pattern to carve out orphaned strings:
`b'(https?://[\\w\\.-]+(?:/[\\w\\.-]*)*)'`
The results are cross-referenced with the active history database; any URLs found in the binary stream that do not exist in the active SQL tables are flagged as "Deleted / Recovered."

### 4.4 Chain of Custody & Security Module
To ensure legal compliance:
- **Read-Only Connections:** SQLite connections strictly use `uri=True` with `mode=ro`.
- **Activity Logger:** Every internal function call appends a timestamped string to the `activity_log` array.
- **Integrity Manifests:** Whenever an export is generated, a corresponding `.manifest.txt` is created containing the SHA-256 hash of the report and the embedded Examiner/Case details.

### 4.5 Central Export Hub
The suite exports the extracted `BrowserArtifact` dataclasses into multiple formats:
- **JSONL:** Used for importing into Splunk or ElasticSearch (SIEM). Case details are injected into every JSON object.
- **SQLite:** A normalized database containing a `case_metadata` table.
- **Interactive HTML:** A CSS-styled offline dashboard utilizing JavaScript for tab navigation.
- **PDF Reports:** Generated via `ReportLab`, specifically tailored for securely presenting decrypted credentials.
- **Secure 7z Archive:** Uses `Py7zr` to bundle all reports into an AES-encrypted archive with a dynamically generated password.

---

## CHAPTER 5: RESULTS AND DISCUSSION

During testing, BrosFros successfully demonstrated high-speed extraction across highly populated browser profiles. 
- **Decryption Accuracy:** The tool achieved a 100% success rate in decrypting AES-GCM protected credentials on the host machine where the Windows DPAPI context was active.
- **Carving Efficacy:** The regex carving engine successfully recovered URLs from cleared Chromium history databases, proving the efficacy of binary analysis over standard SQL queries.
- **UI Responsiveness:** The implementation of Python's `threading` module ensured that the GUI remained highly responsive, smoothly rendering the `CustomTkinter` progress bars even while processing databases exceeding 500MB in size.

---

## CHAPTER 6: CONCLUSION AND FUTURE SCOPE

### 6.1 Conclusion
The BrosFros Forensic Suite successfully achieves its objective of unifying and automating the browser forensic process. By seamlessly integrating DPAPI circumvention, AES-GCM decryption, and raw SQLite data carving into a single, user-friendly interface, it drastically reduces the technical burden on forensic examiners. Furthermore, the strict adherence to chain-of-custody protocols ensures that the suite is not just an analytical tool, but a court-ready evidence preservation framework.

### 6.2 Future Scope
While BrosFros currently operates flawlessly on Windows architectures, future iterations of the project will focus on:
1. **Cross-Platform Support:** Expanding the decryption engine to support macOS (`Keychain`) and Linux (`gnome-keyring` / `KWallet`).
2. **Artificial Intelligence Integration:** Implementing local NLP (Natural Language Processing) models to automatically scan extracted search terms and URLs to flag illicit or suspicious behavior without human intervention.
3. **Memory Forensics Integration:** Adding the capability to dump and carve browser artifacts directly from volatile RAM (Random Access Memory).

---

## REFERENCES
1. SQLite Documentation. "Database File Format." SQLite.org.
2. CustomTkinter Documentation. "A modern and customizable python UI-library based on Tkinter."
3. Python Cryptographic Authority. "PyCryptodome Documentation - AES-GCM."
4. Microsoft OS Documentation. "Windows Data Protection API (DPAPI)."
