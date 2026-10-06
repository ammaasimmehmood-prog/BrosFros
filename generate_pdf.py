import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT

def generate_pdf():
    pdf_path = r"C:\Users\Aasim Mehmood Mirza\Desktop\BrosFros (Chromium, Firefox, IE) v2\BrosFros_Synopsis_Report.pdf"
    doc = SimpleDocTemplate(pdf_path, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    
    styles = getSampleStyleSheet()
    
    # Custom Styles using Times-Roman
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontName='Times-Bold',
        fontSize=18,
        alignment=TA_CENTER,
        spaceAfter=20
    )
    
    center_bold = ParagraphStyle(
        'CenterBold',
        parent=styles['Normal'],
        fontName='Times-Bold',
        fontSize=12,
        alignment=TA_CENTER,
        spaceAfter=10
    )
    
    center_normal = ParagraphStyle(
        'CenterNormal',
        parent=styles['Normal'],
        fontName='Times-Roman',
        fontSize=12,
        alignment=TA_CENTER,
        spaceAfter=6
    )
    
    heading_style = ParagraphStyle(
        'HeadingStyle',
        parent=styles['Heading2'],
        fontName='Times-Bold',
        fontSize=14,
        alignment=TA_LEFT,
        spaceBefore=15,
        spaceAfter=10
    )
    
    subheading_style = ParagraphStyle(
        'SubHeadingStyle',
        parent=styles['Heading3'],
        fontName='Times-Bold',
        fontSize=12,
        alignment=TA_LEFT,
        spaceBefore=10,
        spaceAfter=6
    )
    
    body_style = ParagraphStyle(
        'BodyStyle',
        parent=styles['Normal'],
        fontName='Times-Roman',
        fontSize=12,
        alignment=TA_JUSTIFY,
        spaceAfter=8,
        leading=16
    )

    bullet_style = ParagraphStyle(
        'BulletStyle',
        parent=styles['Normal'],
        fontName='Times-Roman',
        fontSize=12,
        alignment=TA_LEFT,
        spaceAfter=4,
        leading=16,
        leftIndent=20
    )

    elements = []

    # Title Page / Header Elements
    elements.append(Paragraph("PROJECT SYNOPSIS REPORT", title_style))
    elements.append(Spacer(1, 10))
    
    elements.append(Paragraph("<b>Title:</b> BrosFros: A Multi-Engine Browser Forensic Suite with Automated Credential Decryption and Deleted Artifact Recovery.", center_bold))
    elements.append(Spacer(1, 5))
    
    elements.append(Paragraph("<b>Degree:</b> M.TECH in CYBER FORENSICS", center_normal))
    elements.append(Paragraph("<b>Batch:</b> 2025-2027 | 2nd Semester (Session 2026)", center_normal))
    elements.append(Spacer(1, 15))
    
    elements.append(Paragraph("<b>Submitted by</b>", center_normal))
    elements.append(Paragraph("<b>Aasim Mehmood Mirza</b>", center_bold))
    elements.append(Paragraph("<b>NDU202400263</b>", center_bold))
    elements.append(Spacer(1, 15))
    
    elements.append(Paragraph("<b>National Institute of Electronics and Information Technology (NIELIT), Srinagar</b>", center_bold))
    elements.append(Spacer(1, 30))

    # 1. Area of Interest
    elements.append(Paragraph("1. Area of Interest", heading_style))
    elements.append(Paragraph("The proposed project falls under multiple interdisciplinary domains, primarily <b>Cyber Security</b> and <b>Digital Forensics</b>. It specifically focuses on:", body_style))
    areas = ["User Behavior Analysis", "Activity Monitoring", "Data Recovery (Carving)", "Cryptographic Verification & Chain of Custody"]
    for area in areas:
        elements.append(Paragraph(f"• {area}", bullet_style))
    
    # 2. Abstract
    elements.append(Paragraph("2. Abstract", heading_style))
    abstract_text = "Web browsers act as the primary gateway to the internet, making them critical sources of digital evidence in modern cybercrime investigations. Suspects often attempt to conceal their activities by deleting browsing history, clearing cookies, or using anti-forensic techniques. <b>BrosFros</b> is a proposed multi-engine browser forensic suite designed to automate the extraction, decryption, and recovery of digital artifacts across over a dozen different web browsers. By integrating automated credential decryption (bypassing DPAPI restrictions) and SQLite data carving for deleted artifact recovery, BrosFros drastically reduces the time and technical overhead required by forensic investigators while maintaining strict legal chain-of-custody protocols."
    elements.append(Paragraph(abstract_text, body_style))

    # 3. Problem Statement
    elements.append(Paragraph("3. Problem Statement", heading_style))
    elements.append(Paragraph("Current browser forensic investigations face several critical bottlenecks:", body_style))
    problems = [
        "<b>Fragmentation:</b> Investigators must manually juggle different tools to analyze Chromium-based (Chrome, Edge, Brave) and Gecko-based (Firefox) browsers.",
        "<b>Encryption:</b> Critical evidence such as saved credentials and cookies are heavily encrypted using OS-level cryptographic keys (e.g., Windows DPAPI, AES-GCM), rendering raw database extraction useless without automated decryption mechanisms.",
        "<b>Anti-Forensics:</b> Suspects frequently clear their history. Standard forensic tools often fail to recover deleted records hidden within the unallocated spaces of SQLite databases.",
        "<b>Data Integrity:</b> Extracting data directly from live systems risks altering the evidence, invalidating it in a court of law."
    ]
    for i, prob in enumerate(problems, 1):
        elements.append(Paragraph(f"{i}. {prob}", bullet_style))

    # 4. Proposed Solution & Objectives
    elements.append(Paragraph("4. Proposed Solution & Objectives", heading_style))
    elements.append(Paragraph("<b>BrosFros</b> solves these challenges by providing a unified, read-only forensic framework. The primary objectives of this suite include:", body_style))
    objectives = [
        "<b>Multi-Engine Support:</b> Automatic detection and extraction from 14+ browsers including Chrome, Edge, Firefox, Brave, Vivaldi, Opera, and legacy Internet Explorer.",
        "<b>Automated Credential Decryption:</b> Programmatic extraction of the OS Master Key from the browser's Local State file to decrypt AES-256-GCM protected passwords and cookies on-the-fly.",
        "<b>Deleted Artifact Recovery (Data Carving):</b> Utilizing advanced Regular Expression (Regex) carving to scan raw SQLite binary files to recover deleted URLs and timestamps.",
        "<b>Comprehensive Artifact Extraction:</b> Parsing Downloads, Bookmarks, Search Terms, Autofill data, Web Permissions, Top Sites, and Network Predictors.",
        "<b>Forensic Integrity:</b> Implementing a strict 'Forensic Mode' that isolates the host system, queries databases in read-only mode, logs every investigator action, and generates MD5/SHA-256 cryptographic hashes for all extracted evidence."
    ]
    for obj in objectives:
        elements.append(Paragraph(f"• {obj}", bullet_style))

    # 5. System Architecture
    elements.append(Paragraph("5. System Architecture and Methodology", heading_style))
    elements.append(Paragraph("The application follows a strict Model-View-Controller (MVC) architecture, bifurcated into a Backend Forensic Engine and a Frontend Dashboard.", body_style))
    
    elements.append(Paragraph("Phase 1: Evidence Acquisition & Preservation", subheading_style))
    elements.append(Paragraph("• <b>Detection:</b> The engine scans %APPDATA% and %LOCALAPPDATA% for known browser profiles.", bullet_style))
    elements.append(Paragraph("• <b>Preservation:</b> Source databases are cryptographically hashed (MD5/SHA-256). Files are securely copied to a volatile temporary directory to prevent altering the original evidence.", bullet_style))

    elements.append(Paragraph("Phase 2: Analysis & Decryption", subheading_style))
    elements.append(Paragraph("• <b>Data Parsing:</b> SQLite databases are queried to extract structured data.", bullet_style))
    elements.append(Paragraph("• <b>Decryption Engine:</b> The Windows Cryptography API (win32crypt) is leveraged to unlock the DPAPI-protected Master Key, which is then fed into a PyCryptodome AES-GCM cipher to decrypt passwords and session cookies.", bullet_style))
    elements.append(Paragraph("• <b>Carving Engine:</b> Binary byte-scanning is performed on the SQLite files to extract string-matched URLs that have been flagged as deleted by the database schema.", bullet_style))

    elements.append(Paragraph("Phase 3: Reporting & Chain of Custody", subheading_style))
    elements.append(Paragraph("• <b>Activity Logging:</b> Every step taken by the investigator is logged with exact timestamps.", bullet_style))
    elements.append(Paragraph("• <b>Central Export Hub:</b> Data is dynamically exported to multiple formats including JSONL, SQLite, HTML/PDF, and a Secure 7z AES-encrypted archive.", bullet_style))

    # 6. Tools & Technologies
    elements.append(Paragraph("6. Tools & Technologies", heading_style))
    techs = [
        "<b>Programming Language:</b> Python 3.11+",
        "<b>Frontend UI Framework:</b> CustomTkinter (Modern GUI toolkit)",
        "<b>Database Management:</b> SQLite3",
        "<b>Cryptography:</b> PyCryptodome, win32crypt (Windows API)",
        "<b>Data Visualization & Reporting:</b> Matplotlib, XlsxWriter, ReportLab, HTML5/CSS3",
        "<b>Archiving:</b> Py7zr (7-Zip implementation)"
    ]
    for tech in techs:
        elements.append(Paragraph(f"• {tech}", bullet_style))

    # 7. Conclusion & Future Scope
    elements.append(Paragraph("7. Conclusion & Future Scope", heading_style))
    elements.append(Paragraph("BrosFros aims to bridge the gap between complex cryptographic decryption and rapid forensic analysis. By automating the extraction and recovery of volatile browser data, it allows investigators to quickly build timelines of user behavior.", body_style))
    elements.append(Paragraph("<b>Future Enhancements</b> may include cross-platform support for Linux and macOS, and integration with AI-driven Natural Language Processing (NLP) to automatically categorize malicious search terms and flag suspicious browsing activity.", body_style))

    doc.build(elements)
    print(f"PDF successfully generated at: {pdf_path}")

if __name__ == "__main__":
    generate_pdf()
