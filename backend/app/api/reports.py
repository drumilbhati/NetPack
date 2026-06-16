import io
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Response
from fpdf import FPDF

from app.api.cases import mock_cases

router = APIRouter()

# Mock evidence data for demonstration
mock_evidence = {
    "sample-case-uuid": [
        {
            "filename": "suspicious_traffic.pcap",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "size": "45.2 MB",
            "anomalies": ["Beaconing detected to 192.168.1.100", "Large DNS query strings"]
        }
    ]
}

class ForensicReport(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 15)
        self.cell(0, 10, 'NetPack Forensic Analysis Report', border=True, align='C', new_x="LMARGIN", new_y="NEXT")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()} | Generated on {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")} UTC', align='C')

@router.get("/{case_id}")
async def generate_report(case_id: str):
    # Find the case in mock data
    case = next((c for c in mock_cases if c.id == case_id), None)
    
    # For demo purposes, if it's the first mock case or empty, let's allow a "sample" report
    if not case:
        if case_id == "sample":
            case = type('obj', (object,), {
                'id': 'sample-case-uuid',
                'title': 'Sample Investigation',
                'description': 'A sample case for testing report generation.',
                'created_at': datetime.now(timezone.utc)
            })
        else:
            raise HTTPException(status_code=404, detail="Case not found")

    evidence_list = mock_evidence.get(case.id, [
        {
            "filename": "unknown_capture.pcap",
            "sha256": "8b92b6... (Sample Hash)",
            "size": "0 MB",
            "anomalies": ["No anomalies found in sample data"]
        }
    ])

    pdf = ForensicReport()
    pdf.add_page()
    
    # Case Details Section
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, 'Case Details', new_x="LMARGIN", new_y="NEXT")
    pdf.set_font('helvetica', '', 10)
    pdf.cell(0, 6, f'Case ID: {case.id}', new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f'Title: {case.title}', new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f'Description: {case.description}', new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f'Created At: {case.created_at.strftime("%Y-%m-%d %H:%M:%S")} UTC', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Investigator Section (Mocked)
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, 'Lead Investigator', new_x="LMARGIN", new_y="NEXT")
    pdf.set_font('helvetica', '', 10)
    pdf.cell(0, 6, 'Name: Agent Gemini', new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, 'Agency: NetPack Digital Forensics Unit', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Evidence & Hash Section
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, 'Evidence Summary', new_x="LMARGIN", new_y="NEXT")
    for ev in evidence_list:
        pdf.set_font('helvetica', 'B', 10)
        pdf.cell(0, 6, f'File: {ev["filename"]}', new_x="LMARGIN", new_y="NEXT")
        pdf.set_font('helvetica', '', 10)
        pdf.cell(0, 6, f'SHA-256: {ev["sha256"]}', new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f'Size: {ev["size"]}', new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font('helvetica', 'I', 10)
        pdf.cell(0, 6, 'Detected Anomalies:', new_x="LMARGIN", new_y="NEXT")
        for anomaly in ev["anomalies"]:
            pdf.cell(0, 6, f' - {anomaly}', new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # Certification Section
    pdf.ln(10)
    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(0, 6, 'Certification:', new_x="LMARGIN", new_y="NEXT")
    pdf.set_font('helvetica', 'I', 9)
    pdf.multi_cell(0, 5, 'I hereby certify that this report is a true and accurate representation of the digital evidence analyzed by the NetPack platform. The integrity of the original evidence has been maintained via cryptographic hashing.')

    # Return PDF as a response
    pdf_output = pdf.output()
    return Response(
        content=pdf_output,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=NetPack_Report_{case_id}.pdf"}
    )
