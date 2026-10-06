# pyrefly: ignore [missing-import]
import customtkinter as ctk
import os
import sys
import platform
import threading
import json
import sqlite3
import pandas as pd
from tkinter import messagebox, filedialog, ttk
from PIL import Image, ImageDraw, ImageOps
from collections import Counter
from forensics_engine import ForensicEngine, BrowserArtifact

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# --- Theme and Configuration ---
APP_VERSION = "v2026.01"
ORANGE = "#FF8C00"
CREAM = "#F5F5DC"
DARK_GREEN = "#006400"
LIGHT_BG = "#ebebeb" 
DARK_BG = "#1a1a1a"
BLACK = "#000000"
WHITE = "#FFFFFF"
GREEN = "#00FF00"
RED = "#FF0000"

# --- Font Configuration ---
FONT_NORMAL = ("Roboto", 14)
FONT_BOLD = ("Roboto", 14, "bold")
DATA_FONT = ("Roboto", 11)
DATA_FONT_BOLD = ("Roboto", 11, "bold")
TITLE_FONT = ("Roboto", 28, "bold")
STATUS_FONT = ("Roboto", 12)

# --- Set Default Theme ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class BrosFrosApp(ctk.CTk):
    """Main application controller."""
    def __init__(self):
        super().__init__()
        self.title("BrosFros Forensic Suite")
        
        # Initial compact size
        self.app_width = 900
        self.app_height = 650
        self.center_window()
        
        self.engine = ForensicEngine()
        self.logo_ctk_image = None
        self.case_details = {}
        self.analysis_results = []
        self.manifest_path = ""
        self.watchlist = []

        self.load_logo()
        
        self.container = ctk.CTkFrame(self, corner_radius=0, border_width=0)
        self.container.pack(fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)
        
        self.frames = {}
        for F in (WelcomePage, CaseManagementPage, DashboardPage):
            frame = F(self.container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(WelcomePage)



    def center_window(self):
        self.update_idletasks()
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width // 2) - (self.app_width // 2)
        y = (screen_height // 2) - (self.app_height // 2)
        self.geometry(f"{self.app_width}x{self.app_height}+{x}+{y}")

    def resize_for_dashboard(self):
        self.app_width = 1200
        self.app_height = 750
        self.center_window()

    def show_frame(self, cont):
        frame = self.frames[cont]
        if cont == DashboardPage:
            self.resize_for_dashboard()
        if hasattr(frame, 'update_on_show'):
            frame.update_on_show()
        frame.tkraise()

    def load_logo(self):
        try:
            logo_path = resource_path("logo.png")
            if os.path.exists(logo_path):
                img = Image.open(logo_path).convert("RGBA")
                size = (200, 200)
                img = img.resize(size, Image.LANCZOS)
                mask = Image.new('L', size, 0)
                draw = ImageDraw.Draw(mask)
                draw.ellipse((0, 0) + size, fill=255)
                output = ImageOps.fit(img, mask.size, centering=(0.5, 0.5))
                output.putalpha(mask)
                self.logo_ctk_image = ctk.CTkImage(output, size=(100, 100))
        except Exception as e:
            print(f"Error loading logo: {e}")

    def set_case_details(self, details):
        self.case_details = details
        self.engine.case_details = details
        browser_list = ", ".join([b['name'] for b in self.engine.browsers])
        self.engine.log_event("Case Details Set", f"Case: {details.get('Case Number')}, Examiner: {details.get('Examiner Name')}, Browsers Detected: {browser_list}")

    def change_theme(self, new_theme):
        ctk.set_appearance_mode(new_theme)
        is_dark = (new_theme == "Dark")
        bg_color = DARK_BG if is_dark else LIGHT_BG
        text_color = WHITE if is_dark else BLACK
        
        self.configure(fg_color=bg_color)
        self.container.configure(fg_color=bg_color)
        self._update_widget_colors(self, text_color, bg_color)
        
        dashboard = self.frames[DashboardPage]
        dashboard.update_browser_list_ui(text_color)
        dashboard.update_overview_stats(text_color)
        dashboard._setup_table_styles(text_color)

    def _update_widget_colors(self, parent, text_color, bg_color):
        for child in parent.winfo_children():
            if isinstance(child, (ctk.CTkFrame, ctk.CTkScrollableFrame, WelcomePage, CaseManagementPage, DashboardPage)):
                if not getattr(child, "_is_transparent", False):
                    try: child.configure(fg_color=bg_color)
                    except Exception: pass
            if isinstance(child, (ctk.CTkLabel, ctk.CTkButton, ctk.CTkCheckBox, ctk.CTkRadioButton, ctk.CTkEntry, ctk.CTkTextbox, ctk.CTkOptionMenu)):
                try: child.configure(text_color=text_color)
                except Exception: pass
            self._update_widget_colors(child, text_color, bg_color)

class WelcomePage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, corner_radius=0, border_width=0)
        self.controller = controller
        self._is_transparent = False

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        main_container = ctk.CTkFrame(self, border_width=0)
        main_container.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        
        scroll_container = ctk.CTkScrollableFrame(main_container, border_width=0, fg_color="transparent")
        scroll_container.pack(fill="both", expand=True)

        self.logo_display = ctk.CTkLabel(scroll_container, text="")
        self.logo_display.pack(pady=(0, 10))


        # Main Title
        title_text = "A Multi-Engine Browser Forensic Suite\nwith Automated Credential Decryption and Deleted Artifact Recovery"
        ctk.CTkLabel(scroll_container, text=title_text, font=("Roboto", 22, "bold"), justify="center", wraplength=900).pack(pady=(0, 15))
        
        # Authors Box
        authors_frame = ctk.CTkFrame(scroll_container, border_width=1, border_color=ORANGE, fg_color="transparent", corner_radius=10)
        authors_frame.pack(pady=(0, 20), padx=40, fill="x")
        ctk.CTkLabel(authors_frame, text="PROJECT INVESTIGATORS", font=("Courier", 12, "bold"), text_color="gray").pack(pady=(10, 5))
        
        authors_text = "Aasim Mehmood Mirza¹*, Dr. Fayaz Ahmad fayaz², Dr. Syed Mufassir Yaseen³, Er. Abdul Basit⁴"
        ctk.CTkLabel(authors_frame, text=authors_text, font=("Roboto", 16, "bold"), text_color=ORANGE, justify="center", wraplength=800).pack(pady=(0, 10))

        # Abstract Box
        abstract_frame = ctk.CTkFrame(scroll_container, border_width=1, border_color="#333333", corner_radius=10)
        abstract_frame.pack(pady=(0, 20), padx=40, fill="x")
        
        header_frame = ctk.CTkFrame(abstract_frame, height=30, corner_radius=10, fg_color="#333333")
        header_frame.pack(fill="x")
        ctk.CTkLabel(header_frame, text=">_ ROOT_DIR/ABSTRACT", font=("Courier", 12, "bold"), text_color=WHITE).pack(side="left", padx=10)

        abstract_text = (
            "This project presents a comprehensive, multi-engine browser forensic suite designed to automate the extraction, "
            "decryption, and carving of digital artifacts. Supporting over 14 browsers, the tool streamlines the investigative "
            "process by programmatically unlocking DPAPI-protected Master Keys, enabling on-the-fly decryption of passwords "
            "and cookies. It incorporates SQLite data carving techniques utilizing Regex to recover deleted URLs from unallocated "
            "database space. Engineered with strict chain-of-custody protocols—including read-only 'Forensic Mode', cryptographic "
            "hashing (MD5/SHA-256), and activity logging—this suite ensures that all extracted evidence remains legally admissible."
        )
        abstract_label = ctk.CTkLabel(abstract_frame, text=abstract_text, font=("Roboto", 15), justify="left", wraplength=800)
        abstract_label.pack(pady=15, padx=20)
        
        # Features Grid
        features_frame = ctk.CTkFrame(scroll_container, fg_color="transparent")
        features_frame.pack(pady=(0, 20))
        features = ["[ AES-256 Decryption ]", "[ DPAPI Extraction ]", "[ SQLite Binary Carving ]", "[ Chain of Custody ]"]
        for i, f in enumerate(features):
            ctk.CTkLabel(features_frame, text=f, font=("Courier", 12, "bold"), text_color=GREEN).grid(row=i//2, column=i%2, padx=10, pady=5)
        
        # Start Button
        start_btn = ctk.CTkButton(scroll_container, text="INITIALIZE FORENSIC ENGINE", font=("Courier", 18, "bold"), fg_color=DARK_GREEN, hover_color=GREEN, text_color=WHITE, height=50, width=350, border_width=2, border_color=GREEN, corner_radius=5, command=lambda: self.controller.show_frame(CaseManagementPage))
        start_btn.pack(pady=20)

    def update_on_show(self):
        if self.controller.logo_ctk_image:
            self.logo_display.configure(image=self.controller.logo_ctk_image)

class CaseManagementPage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, corner_radius=0, border_width=0)
        self.controller = controller
        self._is_transparent = False

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        main_container = ctk.CTkFrame(self, border_width=0)
        main_container.grid(row=0, column=0)

        self.logo_display = ctk.CTkLabel(main_container, text="")
        self.logo_display.pack(pady=(0, 10))

        ctk.CTkLabel(main_container, text="Case Management", font=TITLE_FONT).pack(pady=(0, 20))
        
        content_frame = ctk.CTkFrame(main_container, width=500, border_width=0)
        content_frame.pack(pady=10, padx=20)
        
        ctk.CTkLabel(content_frame, text="Create New Case", font=FONT_BOLD).grid(row=0, column=0, columnspan=2, pady=15)
        
        self.case_entries = {}
        fields = ["Case Number", "Evidence ID", "Examiner Name"]
        for i, field in enumerate(fields):
            ctk.CTkLabel(content_frame, text=field, font=FONT_NORMAL).grid(row=i+1, column=0, sticky="w", padx=20, pady=8)
            entry = ctk.CTkEntry(content_frame, font=FONT_NORMAL, width=300)
            entry.grid(row=i+1, column=1, sticky="ew", padx=20, pady=8)
            self.case_entries[field] = entry

        ctk.CTkLabel(content_frame, text="Purpose of Investigation", font=FONT_NORMAL).grid(row=len(fields)+1, column=0, sticky="nw", padx=20, pady=8)
        self.purpose_entry = ctk.CTkTextbox(content_frame, font=FONT_NORMAL, width=300, height=100)
        self.purpose_entry.grid(row=len(fields)+1, column=1, sticky="ew", padx=20, pady=8)

        ctk.CTkButton(content_frame, text="Proceed", font=FONT_BOLD, fg_color=ORANGE, text_color=WHITE, height=40, border_width=0, command=self.start_new_case).grid(row=len(fields)+2, column=0, columnspan=2, pady=20)

    def update_on_show(self):
        if self.controller.logo_ctk_image:
            self.logo_display.configure(image=self.controller.logo_ctk_image)

    def start_new_case(self):
        details = {field: entry.get() for field, entry in self.case_entries.items()}
        details["Purpose of Investigation"] = self.purpose_entry.get("1.0", "end-1c")
        if not all(details.values()):
            messagebox.showwarning("Incomplete Information", "Please fill all fields for the new case.")
            return
        self.controller.set_case_details(details)
        self.show_disclaimer()

    def show_disclaimer(self):
        disclaimer = ctk.CTkToplevel(self); disclaimer.title("Legal & Ethical Use Disclaimer")
        disclaimer.attributes("-topmost", True); disclaimer.protocol("WM_DELETE_WINDOW", lambda: sys.exit())
        disclaimer.resizable(False, False)
        
        is_dark = ctk.get_appearance_mode() == "Dark"
        curr_bg = DARK_BG if is_dark else LIGHT_BG
        curr_text = WHITE if is_dark else BLACK

        main_frame = ctk.CTkFrame(disclaimer, fg_color=curr_bg, corner_radius=0, border_width=0)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        if self.controller.logo_ctk_image:
            ctk.CTkLabel(main_frame, image=self.controller.logo_ctk_image, text="").pack(pady=(10,0))

        ctk.CTkLabel(main_frame, text="Legal & Ethical Use Disclaimer", font=("Roboto", 20, "bold"), text_color=ORANGE).pack(pady=(10, 15))
        
        sections = {
            "Allowed Purpose:": ["1. Digital Forensics & Incident Response.", "2. Academic Research & Personal Educational Use."],
            "Legal Use:": ["1. You must have explicit legal authority to analyze data.", "2. This tool shall not be used for unauthorized surveillance or data theft."],
            "Ethical Use:": ["1. You must respect privacy and data protection laws.", "2. The user assumes all responsibility for any misuse of this software."]
        }
        for title, points in sections.items():
            ctk.CTkLabel(main_frame, text=title, font=FONT_BOLD, text_color=curr_text, justify="left").pack(anchor="w", pady=(10,2), padx=10)
            for point in points:
                ctk.CTkLabel(main_frame, text=point, text_color=curr_text, font=FONT_NORMAL, justify="left").pack(anchor="w", padx=25)

        agree_var = ctk.BooleanVar()
        accept_button = ctk.CTkButton(main_frame, text="Accept", state="disabled", border_width=0, command=lambda: (disclaimer.destroy(), self.controller.show_frame(DashboardPage)))
        def toggle_accept(): accept_button.configure(state="normal" if agree_var.get() else "disabled")
        ctk.CTkCheckBox(main_frame, text="I have read and agree to the terms.", variable=agree_var, command=toggle_accept, text_color=curr_text).pack(pady=15)
        accept_button.pack(pady=10)
        
        disclaimer.update_idletasks()
        width, height = disclaimer.winfo_reqwidth(), disclaimer.winfo_reqheight()
        x, y = (self.winfo_screenwidth() // 2) - (width // 2), (self.winfo_screenheight() // 2) - (height // 2)
        disclaimer.geometry(f"{width}x{height}+{x}+{y}"); disclaimer.grab_set()

class DashboardPage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, corner_radius=0, border_width=0)
        self.controller = controller
        self._is_transparent = False
        self.browsers_visible = True
        self.config_saved = False
        self.current_frame_name = "Configuration"
        self.build_full_dashboard()

    def update_on_show(self):
        self.update_status_bar()
        self.update_browser_list_ui()
        self.update_scan_results('history')
        self.update_scan_results('credentials')
        self.update_scan_results('deep_scan')
        self.update_overview_stats()

    def build_full_dashboard(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_columnconfigure(1, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0, border_width=0)
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsw")
        self.sidebar.pack_propagate(False)
        
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, border_width=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)
        
        # Details Panel
        self.details_panel = ctk.CTkFrame(self.main_frame, width=300, corner_radius=0, border_width=0)
        self.details_panel.pack_propagate(False)
        self.panel_relx = 1.3
        self.details_panel.place(relx=self.panel_relx, rely=0.0, relheight=1.0, anchor="ne")
        ctk.CTkLabel(self.details_panel, text="Artifact Details", font=FONT_BOLD).pack(pady=20)
        self.details_text = ctk.CTkTextbox(self.details_panel, font=DATA_FONT, wrap="word")
        self.details_text.pack(fill="both", expand=True, padx=10, pady=10)
        ctk.CTkButton(self.details_panel, text="Close", fg_color=RED, hover_color="#cc0000", command=self.hide_details).pack(pady=10)
        
        self.status_bar = ctk.CTkFrame(self, height=30, corner_radius=0, border_width=0)
        self.status_bar.grid(row=1, column=1, sticky="ew")
        self.status_label_user = ctk.CTkLabel(self.status_bar, text="", font=STATUS_FONT)
        self.status_label_user.pack(side="left", padx=10)
        
        self.progress_bar = ctk.CTkProgressBar(self.status_bar, mode="indeterminate", width=200, progress_color=ORANGE)
        self.progress_bar.set(0)
        self.progress_bar.pack_forget()

        self.version_label = ctk.CTkLabel(self.status_bar, text=f"Version: {APP_VERSION}", font=STATUS_FONT)
        self.version_label.pack(side="right", padx=10)

        self.content_frames = {}
        nav_items = ["Configuration", "History Scan", "Deep Artifacts", "Credential Decryption", "Investigator Timeline", "Overview"]
        for name in nav_items:
            frame = ctk.CTkFrame(self.main_frame, border_width=0)
            frame._is_transparent = True
            self.content_frames[name] = frame
            frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=0)

        self.build_sidebar(nav_items)
        self.build_overview_frame()
        self.build_timeline_frame()
        self.build_browser_scan_frame()
        self.build_credential_frame()
        self.build_deep_artifacts_frame()
        self.build_settings_frame()
        
        self._setup_table_styles(WHITE)
        self.select_frame("Configuration")

    def _setup_table_styles(self, text_color):
        is_dark = ctk.get_appearance_mode() == "Dark"
        tree_bg = DARK_BG if is_dark else WHITE
        alt_bg = "#2a2a2a" if is_dark else "#f0f0f0"
        
        style = ttk.Style()
        style.theme_use("alt")
        style.configure("Treeview", background=tree_bg, foreground=text_color, fieldbackground=tree_bg, font=DATA_FONT, rowheight=35, borderwidth=0)
        style.map('Treeview', background=[('selected', ORANGE)], foreground=[('selected', WHITE)])
        style.configure("Treeview.Heading", background=ORANGE, foreground=WHITE, font=DATA_FONT_BOLD, borderwidth=0, padding=5)
        style.map("Treeview.Heading", background=[('active', "#e67e22")])
        
        # We will use tags to create striped rows
        for tree in getattr(self, 'all_trees', []):
            tree.tag_configure('evenrow', background=tree_bg)
            tree.tag_configure('oddrow', background=alt_bg)
            tree.tag_configure('highlight', background="#8b0000", foreground="white")
            tree.tag_configure('bold', font=DATA_FONT_BOLD)

    def build_sidebar(self, nav_items):
        self.logo_label = ctk.CTkLabel(self.sidebar, text="")
        self.logo_label.pack(pady=(20, 15))
        
        # Global Search
        ctk.CTkLabel(self.sidebar, text="Universal Keyword Search", font=("Roboto", 12, "bold"), text_color=ORANGE).pack(pady=(0, 5), padx=20, anchor="w")
        self.search_var = ctk.StringVar()
        self.search_entry = ctk.CTkEntry(self.sidebar, placeholder_text="Search the keyword...", textvariable=self.search_var)
        self.search_entry.pack(fill="x", padx=20, pady=(0, 15))
        self.search_entry.bind("<KeyRelease>", self.on_search)
        
        ctk.CTkButton(self.sidebar, text="Detect Browsers", font=FONT_BOLD, fg_color=ORANGE, text_color=WHITE, border_width=0, command=self.refresh_browsers).pack(fill="x", padx=20, pady=10)

        self.nav_buttons = {}
        nav_labels = {
            "Configuration": "⚙️ Configuration",
            "History Scan": "🔍 History Scan",
            "Deep Artifacts": "🛡️ Deep Artifacts",
            "Credential Decryption": "🔑 Credential Decryption",
            "Investigator Timeline": "🕒 Investigator Timeline",
            "Overview": "📊 Overview"
        }
        for item in nav_items:
            btn = ctk.CTkButton(self.sidebar, text=nav_labels.get(item, item), font=FONT_NORMAL, corner_radius=0, border_width=0, command=lambda name=item: self.select_frame(name))
            btn.pack(fill="x", pady=4)
            self.nav_buttons[item] = btn
            if item != "Configuration":
                btn.configure(state="disabled")
                
        self.browser_toggle_button = ctk.CTkButton(self.sidebar, text="Detected Browsers", font=FONT_BOLD, fg_color=ORANGE, text_color=WHITE, border_width=0, command=self.toggle_browser_list)
        self.browser_toggle_button.pack(fill="x", padx=20, pady=(20, 5))
        
        self.browsers_frame = ctk.CTkScrollableFrame(self.sidebar, height=200, border_width=0)
        self.browsers_frame.pack(fill="x", expand=False, pady=0, padx=20)
        self.update_browser_list_ui()

    def toggle_browser_list(self):
        if self.browsers_visible: self.browsers_frame.pack_forget()
        else: self.browsers_frame.pack(fill="x", expand=False, pady=0, padx=20)
        self.browsers_visible = not self.browsers_visible

    def build_overview_frame(self):
        frame = self.content_frames["Overview"]
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=0, minsize=320)
        frame.grid_rowconfigure(1, weight=1)
        self.overview_title = ctk.CTkLabel(frame, text="Case Summary Overview", font=TITLE_FONT)
        self.overview_title.grid(row=0, column=0, sticky="w")
        
        self.overview_stats_frame = ctk.CTkFrame(frame, border_width=0)
        self.overview_stats_frame._is_transparent = True
        self.overview_stats_frame.grid(row=1, column=0, sticky="nsew", pady=10)

        # Centralized Export Hub
        export_hub = ctk.CTkFrame(frame, width=320, corner_radius=15, border_width=1)
        export_hub.grid(row=1, column=1, sticky="ns", padx=(20, 0), pady=10)
        
        ctk.CTkLabel(export_hub, text="📦 Central Export Hub", font=("Roboto", 18, "bold")).pack(pady=(15, 5))
        ctk.CTkLabel(export_hub, text="Generate Forensic Reports", font=STATUS_FONT, text_color="gray").pack(pady=(0, 15))
        
        buttons_frame = ctk.CTkFrame(export_hub)
        buttons_frame.pack(fill="x", padx=15)
        
        formats = [
            ("📊 Export XLSX", "xlsx"), 
            ("📝 Export JSONL", "jsonl"), 
            ("🗄️ Export SQLite", "sqlite"), 
            ("🌐 Export HTML", "html"), 
            ("📄 Export PDF", "pdf"),
            ("🔐 Credentials PDF", "credentials_pdf"),
            ("📜 Activity Logs", "activity_logs")
        ]
        
        for i, (label, fmt) in enumerate(formats):
            cmd = getattr(self, f"export_{fmt}")
            btn = ctk.CTkButton(buttons_frame, text=label, font=FONT_BOLD, 
                                fg_color=DARK_BG if ctk.get_appearance_mode() == "Dark" else LIGHT_BG, 
                                border_width=1, border_color=ORANGE, hover_color=ORANGE, 
                                command=cmd)
            btn.grid(row=i//2, column=i%2, padx=5, pady=5, sticky="ew")
        
        buttons_frame.grid_columnconfigure((0,1), weight=1)

        # Encrypted 7z Section
        zip_frame = ctk.CTkFrame(export_hub, corner_radius=10, fg_color=DARK_BG if ctk.get_appearance_mode() == "Dark" else "#e0e0e0")
        zip_frame.pack(fill="x", padx=15, pady=(20, 10))
        
        ctk.CTkLabel(zip_frame, text="🔒 Secure 7z Export", font=FONT_BOLD).pack(pady=(10, 5))
        self.zip_pass_entry = ctk.CTkEntry(zip_frame, placeholder_text="Enter Password Prefix...", font=DATA_FONT, height=30)
        self.zip_pass_entry.pack(fill="x", padx=15, pady=(0, 10))
        
        ctk.CTkButton(zip_frame, text="Generate Encrypted Archive", font=FONT_BOLD, fg_color=ORANGE, text_color=WHITE, hover_color="#cc7000", command=self.export_encrypted_full_zip).pack(fill="x", padx=15, pady=(0, 15))
        
        ctk.CTkButton(export_hub, text="📂 Open Export Directory", font=FONT_NORMAL, border_width=1, command=self.open_manifest).pack(fill="x", padx=15, pady=5)

    def _create_scrollable_tree(self, parent, columns):
        container = ctk.CTkFrame(parent, border_width=0)
        container.grid(row=0, column=0, sticky="nsew")
        container.grid_columnconfigure(0, weight=1); container.grid_rowconfigure(0, weight=1)
        tree = ttk.Treeview(container, columns=columns, show='headings')
        for col in columns: tree.heading(col, text=col); tree.column(col, width=120)
        vsb = ctk.CTkScrollbar(container, orientation="vertical", command=tree.yview)
        hsb = ctk.CTkScrollbar(container, orientation="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew"); vsb.grid(row=0, column=1, sticky="ns"); hsb.grid(row=1, column=0, sticky="ew")
        tree.tag_configure('highlight', foreground=RED)
        tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        if not hasattr(self, 'all_trees'): self.all_trees = []
        self.all_trees.append(tree)
        return tree
        
    def hide_details(self):
        self.animate_panel_out()

    def animate_panel_out(self):
        if self.panel_relx < 1.3:
            self.panel_relx += 0.05
            self.details_panel.place(relx=self.panel_relx, rely=0.0, relheight=1.0, anchor="ne")
            self.after(15, self.animate_panel_out)
        else:
            self.panel_relx = 1.3
            self.details_panel.place(relx=self.panel_relx, rely=0.0, relheight=1.0, anchor="ne")

    def animate_panel_in(self):
        self.details_panel.tkraise()
        if self.panel_relx > 1.0:
            self.panel_relx -= 0.05
            self.details_panel.place(relx=self.panel_relx, rely=0.0, relheight=1.0, anchor="ne")
            self.after(15, self.animate_panel_in)
        else:
            self.panel_relx = 1.0
            self.details_panel.place(relx=self.panel_relx, rely=0.0, relheight=1.0, anchor="ne")

    def on_tree_select(self, event):
        tree = event.widget
        selection = tree.selection()
        if not selection: return
        item = tree.item(selection[0])
        values = item.get('values', [])
        columns = tree['columns']
        self.details_text.delete("1.0", "end")
        for col, val in zip(columns, values):
            self.details_text.insert("end", f"{col}:\n{val}\n\n")
        self.animate_panel_in()

    def build_timeline_frame(self):
        frame = self.content_frames["Investigator Timeline"]
        frame.grid_columnconfigure(0, weight=1); frame.grid_rowconfigure(0, weight=1)
        self.timeline_tree = self._create_scrollable_tree(frame, ("Browser", "Type", "URL", "Title", "Timestamp", "Value", "Deep", "Location"))
        self.timeline_tree.tag_configure('bold', font=DATA_FONT_BOLD)
        action_bar = ctk.CTkFrame(frame, border_width=0)
        action_bar.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        btn = ctk.CTkButton(action_bar, text="Refresh Timeline", font=FONT_BOLD, fg_color=ORANGE, text_color=WHITE, border_width=0, command=self.update_timeline)
        btn.pack(side="left")

    def build_browser_scan_frame(self):
        frame = self.content_frames["History Scan"]
        frame.grid_columnconfigure(0, weight=1); frame.grid_rowconfigure(0, weight=1)
        self.history_tree = self._create_scrollable_tree(frame, ("Browser", "Type", "URL", "Title", "Timestamp", "Status", "Deep", "Web Permissions", "Session", "Location"))
        self.history_tree.tag_configure('bold', font=DATA_FONT_BOLD)
        action_bar = ctk.CTkFrame(frame, border_width=0)
        action_bar.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        btn = ctk.CTkButton(action_bar, text="Extract Artifacts", font=FONT_BOLD, fg_color=ORANGE, text_color=WHITE, border_width=0, command=lambda: self.run_scan_thread(scan_type='history'))
        btn.pack(side="left")
        if not hasattr(self, 'scan_buttons'): self.scan_buttons = []
        self.scan_buttons.append(btn)

    def build_credential_frame(self):
        frame = self.content_frames["Credential Decryption"]
        frame.grid_columnconfigure(0, weight=3); frame.grid_rowconfigure(0, weight=1)
        self.cred_tree = self._create_scrollable_tree(frame, ("Browser", "URL", "Username", "Password", "Status", "Deep", "Web Permissions", "Session", "Location"))
        self.cred_tree.tag_configure('bold', font=DATA_FONT_BOLD)
        action_bar = ctk.CTkFrame(frame, border_width=0)
        action_bar.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        btn = ctk.CTkButton(action_bar, text="Scan for Credentials", font=FONT_BOLD, fg_color=ORANGE, text_color=WHITE, border_width=0, command=lambda: self.run_scan_thread(scan_type='credentials'))
        btn.pack(side="left")
        if not hasattr(self, 'scan_buttons'): self.scan_buttons = []
        self.scan_buttons.append(btn)
        
        # Dedicated Export Hub for Credentials
        cred_export_hub = ctk.CTkFrame(frame, width=200, border_width=0); cred_export_hub.grid(row=0, column=1, sticky="ns", padx=(10, 0))
        ctk.CTkLabel(cred_export_hub, text="Export Hub", font=FONT_BOLD).pack(pady=10)
        ctk.CTkButton(cred_export_hub, text="Export Comprehensive PDF", font=FONT_NORMAL, border_width=0, command=self.export_pdf).pack(fill="x", padx=10, pady=5)

    def build_deep_artifacts_frame(self):
        frame = self.content_frames["Deep Artifacts"]
        frame.grid_columnconfigure(0, weight=1); frame.grid_rowconfigure(0, weight=1)
        self.deep_tree = self._create_scrollable_tree(frame, ("Browser", "Type", "URL/Host", "Title/Name", "Value/Path", "Status", "Deep", "Web Permissions", "Session", "Location"))
        self.deep_tree.tag_configure('bold', font=DATA_FONT_BOLD)
        action_bar = ctk.CTkFrame(frame, border_width=0)
        action_bar.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        btn = ctk.CTkButton(action_bar, text="Run Deep Scan", font=FONT_BOLD, fg_color=ORANGE, text_color=WHITE, border_width=0, command=lambda: self.run_scan_thread(scan_type='deep_scan'))
        btn.pack(side="left")
        if not hasattr(self, 'scan_buttons'): self.scan_buttons = []
        self.scan_buttons.append(btn)

    def build_settings_frame(self):
        frame = self.content_frames["Configuration"]
        frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(frame, text="Application Configuration", font=TITLE_FONT).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 20))
        settings_panel = ctk.CTkFrame(frame, border_width=0)
        settings_panel.grid(row=1, column=0, columnspan=2, sticky="ew")
        
        ctk.CTkLabel(settings_panel, text="Theme:", font=FONT_NORMAL).grid(row=0, column=0, sticky="w", padx=5)
        self.theme_menu = ctk.CTkOptionMenu(settings_panel, values=["Light", "Dark"], font=FONT_NORMAL, command=self.controller.change_theme)
        self.theme_menu.grid(row=0, column=1, sticky="w")
        self.theme_menu.set("Dark")
        
        ctk.CTkLabel(settings_panel, text="Keyword Watchlist:", font=FONT_NORMAL).grid(row=1, column=0, sticky="nw", padx=5, pady=10)
        self.watchlist_entry = ctk.CTkTextbox(settings_panel, font=FONT_NORMAL, width=300, height=100)
        self.watchlist_entry.grid(row=1, column=1, sticky="w", pady=10)
        self.watchlist_entry.insert("1.0", ", ".join(self.controller.watchlist))
        ctk.CTkLabel(settings_panel, text="(Separate with commas)", font=STATUS_FONT).grid(row=2, column=1, sticky="w", padx=5)

        ctk.CTkButton(settings_panel, text="Save Settings", font=FONT_BOLD, border_width=0, command=self.save_settings).grid(row=3, column=1, sticky="w", pady=20)

        # Forensic Mode Toggle
        self.forensic_mode_var = ctk.BooleanVar(value=self.controller.engine.forensic_mode)
        self.forensic_mode_switch = ctk.CTkSwitch(settings_panel, text="Forensic Mode (Portable + Write Blocker)", font=FONT_BOLD, variable=self.forensic_mode_var, command=self.toggle_forensic_mode, progress_color=ORANGE)
        self.forensic_mode_switch.grid(row=4, column=0, columnspan=2, sticky="w", pady=20, padx=5)

        ctk.CTkButton(settings_panel, text="Clear Temp Cache", font=FONT_BOLD, border_width=0, command=self.controller.engine.cleanup_temp).grid(row=5, column=0, pady=20)

    def toggle_forensic_mode(self):
        enabled = self.forensic_mode_var.get()
        self.controller.engine.forensic_mode = enabled
        self.controller.engine.log_event("Forensic Mode Toggled", f"New State: {'Enabled' if enabled else 'Disabled'}")
        status = "Enabled" if enabled else "Disabled"
        messagebox.showinfo("Forensic Mode", f"Forensic Mode {status}.\n\nPortable: No traces left on system.\nWrite Blocker: Read-only database access.")

    def save_settings(self):
        watchlist_text = self.watchlist_entry.get("1.0", "end-1c")
        self.controller.watchlist = [k.strip() for k in watchlist_text.split(",") if k.strip()]
        self.controller.engine.watchlist = self.controller.watchlist
        self.controller.engine.log_event("Settings Saved", f"Watchlist: {watchlist_text}")
        
        # Enable other tabs
        self.config_saved = True
        for btn in self.nav_buttons.values():
            btn.configure(state="normal")
        
        # Refresh UI to apply highlighting
        self.update_scan_results('history')
        self.update_scan_results('credentials')
        self.update_scan_results('deep_scan')
        
        messagebox.showinfo("Settings", "Configuration saved. All forensic modules are now enabled.")
        self.select_frame("History Scan")

    def select_frame(self, name):
        if not self.config_saved and name != "Configuration":
            messagebox.showwarning("Configuration Required", "Please save your configuration settings first.")
            return

        is_dark = ctk.get_appearance_mode() == "Dark"
        inactive_color = "#2B2B2B" if is_dark else "#d9d9d9"
        for frame_name, frame in self.content_frames.items():
            frame.grid_remove()
            if frame_name in self.nav_buttons: self.nav_buttons[frame_name].configure(fg_color=inactive_color)
            
        self.content_frames[name].grid()
        self.nav_buttons[name].configure(fg_color=ORANGE)
        self.current_frame_name = name
        
        if name == "Overview": self.update_overview_stats()

    def update_status_bar(self):
        details = self.controller.case_details
        user_info = f"Examiner: {details.get('Examiner Name', 'N/A')} | Case: {details.get('Case Number', 'N/A')}"
        self.status_label_user.configure(text=user_info)

    def refresh_browsers(self):
        self.controller.engine.log_event("Browser Detection", "Manual refresh triggered.")
        self.controller.engine.browsers = self.controller.engine.detect_browsers()
        self.update_browser_list_ui()
        messagebox.showinfo("Refresh", f"Found {len(self.controller.engine.browsers)} browsers.")

    def update_browser_list_ui(self, text_color=None):
        if text_color is None: text_color = WHITE if ctk.get_appearance_mode() == "Dark" else BLACK
        browser_list_text_color = GREEN
        for widget in self.browsers_frame.winfo_children(): widget.destroy()
        if self.controller.logo_ctk_image: self.logo_label.configure(image=self.controller.logo_ctk_image)
        if self.controller.engine.browsers:
            for browser in self.controller.engine.browsers:
                ctk.CTkLabel(self.browsers_frame, text=f"• {browser['name']}", font=FONT_BOLD, text_color=browser_list_text_color, anchor="w").pack(fill="x", padx=10)
        else:
            ctk.CTkLabel(self.browsers_frame, text="None found. Click Detect.", font=FONT_NORMAL, text_color=text_color).pack(fill="x", padx=10)

    def run_scan_thread(self, scan_type):
        self.progress_bar.pack(side="left", padx=20)
        self.progress_bar.start()
        for btn in getattr(self, 'scan_buttons', []):
            btn.configure(state="disabled")
        threading.Thread(target=self.execute_scan, args=(scan_type,), daemon=True).start()

    def execute_scan(self, scan_type):
        try:
            deep_scan = (scan_type == 'deep_scan')
            credentials = (scan_type == 'credentials')
            new_results = self.controller.engine.run_scan(deep_scan=deep_scan, scan_credentials=credentials)
            # Deduplicate against existing results (thread-safe: build batch then hand to main thread)
            existing_data = set(json.dumps(r.data, sort_keys=True, default=str) for r in self.controller.analysis_results)
            batch = []
            for r in new_results:
                r_data_str = json.dumps(r.data, sort_keys=True, default=str)
                if r_data_str not in existing_data:
                    batch.append(r)
                    existing_data.add(r_data_str)
            # Hand the batch to the main thread for safe list mutation
            self.after(0, self._apply_scan_results, batch, scan_type)
        except Exception as e:
            self.controller.engine.log_event("Scan Error", f"Scan '{scan_type}' failed: {str(e)}")
            self.after(0, self._finish_scan_ui, scan_type)

    def _apply_scan_results(self, batch, scan_type):
        """Called on the main thread to safely mutate analysis_results."""
        self.controller.analysis_results.extend(batch)
        self.update_scan_results(scan_type)

    def _finish_scan_ui(self, scan_type):
        """Ensure progress bar stops and buttons re-enable even on error."""
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        for btn in getattr(self, 'scan_buttons', []):
            btn.configure(state="normal")

    def on_search(self, event):
        name = self.current_frame_name
        if name == "History Scan": self.update_scan_results('history')
        elif name == "Deep Artifacts": self.update_scan_results('deep_scan')
        elif name == "Credential Decryption": self.update_scan_results('credentials')
        elif name == "Investigator Timeline": self.update_timeline()

    def update_timeline(self):
        self.timeline_tree.delete(*self.timeline_tree.get_children())
        results = self.controller.analysis_results
        search_query = self.search_var.get().lower()
        
        timeline_items = []
        for item in results:
            d = item.data
            if search_query:
                if not any(search_query in str(v).lower() for v in d.values()) and search_query not in (item.browser_name or "").lower() and search_query not in (item.artifact_type or "").lower():
                    continue
            ts = d.get('Timestamp')
            if ts and str(ts) not in ["Unknown", "N/A"]: 
                timeline_items.append((str(ts), item))
        
        timeline_items.sort(key=lambda x: x[0], reverse=True)
        
        for i, (ts, item) in enumerate(timeline_items):
            d = item.data
            tags = ['evenrow'] if i % 2 == 0 else ['oddrow']
            val = d.get('Value') or d.get('Term') or d.get('File Name') or ""
            self.timeline_tree.insert("", "end", values=(item.browser_name, item.artifact_type, d.get('URL'), d.get('Title'), ts, val, d.get('Deep'), d.get('Location')), tags=tuple(tags))

    def update_scan_results(self, scan_type):
        results = self.controller.analysis_results
        tree_map = {'history': self.history_tree, 'credentials': self.cred_tree, 'deep_scan': self.deep_tree}
        tree = tree_map.get(scan_type)
        if not tree: return
        tree.delete(*tree.get_children())
        
        keywords = [k.lower() for k in self.controller.watchlist]
        search_query = self.search_var.get().lower()
        
        row_idx = 0
        for item in results:
            d = item.data
            
            if search_query:
                if not any(search_query in str(v).lower() for v in d.values()) and search_query not in (item.browser_name or "").lower() and search_query not in (item.artifact_type or "").lower():
                    continue

            tags = ['evenrow'] if row_idx % 2 == 0 else ['oddrow']
            
            # Check for keywords and Dark Web Activity using engine
            match_str = self.controller.engine.check_watchlist(d)
            if str(match_str).startswith("Yes"):
                tags.append('highlight')
                d['Watchlist Match'] = match_str
            else:
                d['Watchlist Match'] = 'No'
            
            if scan_type == 'history' and item.artifact_type == 'History' and d.get('Status') == 'Live':
                if item.browser_name or d.get('Title'): tags.append('bold')
                tree.insert("", "end", values=(item.browser_name, 'History', d.get('URL'), d.get('Title'), str(d.get('Timestamp')), d.get('Status'), d.get('Deep'), d.get('Web Permissions'), d.get('Session'), d.get('Location')), tags=tuple(tags))
                row_idx += 1
            elif scan_type == 'credentials' and item.artifact_type == 'Credential':
                if item.browser_name: tags.append('bold')
                tree.insert("", "end", values=(item.browser_name, d.get('URL'), d.get('Username'), d.get('Password'), d.get('Decryption Status'), d.get('Deep'), d.get('Web Permissions'), d.get('Session'), d.get('Location')), tags=tuple(tags))
                row_idx += 1
            elif scan_type == 'deep_scan' and item.artifact_type in ['Download', 'Bookmark', 'Cookie', 'Search Term', 'Autofill', 'Deleted History', 'Web Permission', 'Extension', 'Top Site', 'Network Predictor']:
                if item.browser_name or d.get('Title'): tags.append('bold')
                tree.insert("", "end", values=(item.browser_name, item.artifact_type, d.get('URL'), d.get('Title'), d.get('Value'), d.get('Status'), d.get('Deep'), d.get('Web Permissions'), d.get('Session'), d.get('Location')), tags=tuple(tags))
                row_idx += 1
        self.update_overview_stats()
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        for btn in getattr(self, 'scan_buttons', []):
            btn.configure(state="normal")
    
    def update_overview_stats(self, text_color=None):
        if text_color is None: text_color = WHITE if ctk.get_appearance_mode() == "Dark" else BLACK
        for widget in self.overview_stats_frame.winfo_children(): widget.destroy()
        results = self.controller.analysis_results
        if not results:
            ctk.CTkLabel(self.overview_stats_frame, text="No scan data available.", font=FONT_BOLD, text_color=text_color).pack()
            return
        left_stats_frame = ctk.CTkFrame(self.overview_stats_frame)
        left_stats_frame.pack(side="left", fill="both", expand=True, padx=10)
        
        history_count = sum(1 for item in results if item.artifact_type == 'History' and item.data.get('Status') == 'Live')
        cred_count = sum(1 for item in results if item.artifact_type == 'Credential')
        deep_count = sum(1 for item in results if item.artifact_type in ['Download', 'Bookmark', 'Cookie', 'Search Term', 'Autofill', 'Deleted History', 'Web Permission', 'Extension', 'Top Site', 'Network Predictor'])
        
        ctk.CTkLabel(left_stats_frame, text=f"Total Artifacts Found: {len(results)}", font=FONT_BOLD, text_color=text_color).pack(anchor="w")
        ctk.CTkLabel(left_stats_frame, text=f"  - Live History: {history_count}", font=FONT_NORMAL, text_color=text_color).pack(anchor="w", padx=10)
        ctk.CTkLabel(left_stats_frame, text=f"  - Saved Credentials: {cred_count}", font=FONT_NORMAL, text_color=text_color).pack(anchor="w", padx=10)
        ctk.CTkLabel(left_stats_frame, text=f"  - Deep Artifacts: {deep_count}", font=FONT_NORMAL, text_color=text_color).pack(anchor="w", padx=10)
        
        # Activity Log Summary
        ctk.CTkLabel(left_stats_frame, text=f"\nActivity Logs (Chain of Custody):", font=FONT_BOLD, text_color=text_color).pack(anchor="w", pady=(10,0))
        ctk.CTkLabel(left_stats_frame, text=f"  - Total Steps Recorded: {len(self.controller.engine.activity_log)}", font=FONT_NORMAL, text_color=text_color).pack(anchor="w", padx=10)
        
        ctk.CTkLabel(left_stats_frame, text="\nBreakdown by Browser:", font=FONT_BOLD, text_color=text_color).pack(anchor="w", pady=(10,0))
        stats = Counter(item.browser_name for item in results)
        for browser, count in stats.items():
            ctk.CTkLabel(left_stats_frame, text=f"  - {browser}: {count} artifacts", font=FONT_NORMAL, text_color=text_color).pack(anchor="w", padx=10)

        # Removed matplotlib bar chart as requested to ensure Export Hub is fully visible.

        # Verified Source Hashes
        hashes = self.controller.engine.source_hashes
        if hashes:
            ctk.CTkLabel(left_stats_frame, text="\nVerified Source Hashes (Chain of Custody):", font=FONT_BOLD, text_color=ORANGE).pack(anchor="w", pady=(15,0))
            for path, h in hashes.items():
                name = os.path.basename(path)
                ctk.CTkLabel(left_stats_frame, text=f"  - {name}: {h}", font=DATA_FONT, text_color=text_color).pack(anchor="w", padx=10)

    def export_xlsx(self): self._run_export(self.controller.engine.generate_report, ".xlsx", "Excel Files")
    def export_jsonl(self): self._run_export(self.controller.engine.generate_jsonl, ".jsonl", "JSONL Files")
    def export_sqlite(self): self._run_export(self.controller.engine.generate_sqlite, ".db", "SQLite Files")
    def export_html(self): self._run_export(self.controller.engine.generate_html, ".html", "HTML Files")
    def export_pdf(self): self._run_export(self.controller.engine.generate_pdf_report, ".pdf", "PDF Files")
    def export_activity_logs(self): self._run_export(self.controller.engine.generate_activity_log_report, ".xlsx", "Excel Files")
    
    def export_credentials_pdf(self):
        if not self.controller.analysis_results:
            messagebox.showwarning("Export Error", "No data to export.")
            return
        creds = [r for r in self.controller.analysis_results if r.artifact_type == "Credential"]
        if not creds:
            messagebox.showwarning("Export Error", "No credentials found to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")], initialdir=os.path.expanduser("~"))
        if not path: return
        try:
            self.controller.engine.generate_pdf_report(path, results=creds)
            self.controller.manifest_path = self.controller.engine.generate_manifest(path)
            messagebox.showinfo("Export Successful", f"Credentials PDF saved to {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"An error occurred: {e}")

    def export_encrypted_full_zip(self):
        prefix = self.zip_pass_entry.get()
        if not prefix:
            messagebox.showwarning("Prefix Required", "Please enter a 7z Password Prefix in the box above.")
            return
        
        # Calculate dynamic password
        steps = len(self.controller.engine.activity_log)
        password = f"{prefix}@{steps}"
        
        path = filedialog.asksaveasfilename(defaultextension=".7z", filetypes=[("Encrypted 7z", "*.7z"), ("All Files", "*.*")], initialdir=os.path.expanduser("~"))
        if not path: return
        
        try:
            self.controller.engine.generate_full_zip(path, password, results=self.controller.analysis_results)
            self.controller.manifest_path = self.controller.engine.generate_manifest(path)
            messagebox.showinfo("Export Successful", f"Encrypted 7z saved.\n\nPassword: {password}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"An error occurred: {e}")

    def _run_export(self, export_method, extension, file_type):
        if not self.controller.analysis_results and "activity" not in str(export_method):
            messagebox.showwarning("Export Error", "No data to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=extension, filetypes=[(file_type, f"*{extension}"), ("All Files", "*.*")], initialdir=os.path.expanduser("~"))
        if not path: return
        try:
            export_method(path, results=self.controller.analysis_results)
            self.controller.manifest_path = self.controller.engine.generate_manifest(path)
            messagebox.showinfo("Export Successful", f"Report saved to {os.path.basename(path)}")
        except Exception as e:
            self.controller.engine.log_event("Export Error", f"Failed to export {extension}: {str(e)}")
            messagebox.showerror("Export Failed", f"An error occurred: {e}")
    
    def open_manifest(self):
        if not self.controller.manifest_path or not os.path.exists(self.controller.manifest_path):
            messagebox.showwarning("Manifest Error", "No export has been performed yet. Export a report first.")
            return
        export_dir = os.path.dirname(self.controller.manifest_path)
        os.startfile(export_dir)

if __name__ == "__main__":
    app = BrosFrosApp()
    app.mainloop()
