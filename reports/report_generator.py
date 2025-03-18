import csv
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit
import textwrap

def format_vulnerabilities(vulns, max_vulns=10):
    """Format vulnerabilities into readable report format."""
    formatted = []
    for i, vuln in enumerate(vulns[:max_vulns]):  # Limit vulnerabilities to 10
        formatted.append(f"🔹 {vuln.get('alert', 'Unknown Alert')} ({vuln.get('risk', 'Unknown Risk')})\n")
        formatted.append(f"      🔸 Evidence: {textwrap.fill(vuln.get('evidence', 'N/A'), width=80)}")
        formatted.append(f"      🔸 Description: {textwrap.fill(vuln.get('description', 'N/A'), width=80)}")
        formatted.append(f"      🔸 Solution: {textwrap.fill(vuln.get('solution', 'N/A'), width=80)}\n")
        formatted.append("\n" + "-" * 80 + "\n")  # Add a line break after each vulnerability for better readability

    return "\n".join(formatted) if formatted else "No critical vulnerabilities found."

def format_list(items):
    """Format list items with bullet points."""
    return "\n".join([f"• {item}" for item in items]) if items else "No data available."

def generate_pdf_report(data, output_path="HackGuard_Report.pdf", max_vulns=10):
    """
    Generates a properly formatted PDF report with spacing and indentation.
    """
    c = canvas.Canvas(output_path, pagesize=letter)
    width, height = letter
    margin = 50
    right_margin = width - margin
    y_position = height - 60  # Start below the title

    # Set default font (Explicitly setting it before drawing text)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(margin, y_position, "📌 HackGuard Security Report")
    y_position -= 40  # More space below title

    def add_section(title, content, spacing=30):
        """Adds a properly formatted section to the PDF with consistent spacing."""
        nonlocal y_position
        if y_position < 100:
            c.showPage()
            c.setFont("Helvetica-Bold", 16)  # Reapply title font on new page
            y_position = height - 50

        c.setFont("Helvetica-Bold", 12)
        c.drawString(margin, y_position, title)
        y_position -= 15

        c.setFont("Helvetica", 10)  # Ensure content font is consistent
        if isinstance(content, list):
            content = format_list(content)  # Convert lists to readable text

        lines = simpleSplit(str(content), "Helvetica", 10, right_margin - margin)  # Wrap text correctly
        for line in lines:
            c.drawString(margin, y_position, line)
            y_position -= 15
            if y_position < 50:
                c.showPage()
                c.setFont("Helvetica", 10)  # Reapply content font on new page
                y_position = height - 50

        y_position -= spacing  # Extra spacing after section

    for row in data:
        if row.startswith("Vulnerabilities:"):
            vuln_list = eval(row.replace("Vulnerabilities:", "").strip())  # Convert string to list
            formatted_vulns = format_vulnerabilities(vuln_list, max_vulns)
            add_section("🔍 Vulnerabilities (Top 10):", formatted_vulns, spacing=30)
        elif row.startswith("Ports:"):
            port_list = eval(row.replace("Ports:", "").strip())
            add_section("🛠 Open Ports:", format_list(port_list), spacing=30)
        elif row.startswith("DNS:"):
            dns_list = eval(row.replace("DNS:", "").strip())
            add_section("🌍 DNS Records:", format_list(dns_list), spacing=30)
        else:
            key, value = row.split(":", 1) if ":" in row else ("Note", row)
            add_section(f"📌 {key.strip()}:", value.strip(), spacing=20)

    c.save()

def generate_csv_report(filename, data):
    with open(filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Scan Results"])
        for row in data:
            writer.writerow([row])