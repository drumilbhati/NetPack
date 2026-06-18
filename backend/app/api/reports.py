import re
import json
from datetime import datetime, timezone
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Response
from fpdf import FPDF

from app.core.database import get_db_conn
from app.dependencies.auth import require_case_access, require_role
from app.schemas.auth import UserContext

router = APIRouter()


class ForensicReport(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 15)
        self.cell(
            0,
            10,
            "NetPack Forensic Analysis Report",
            border=1,
            align="C",
            new_x="LMARGIN",
            new_y="NEXT",
        )
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.cell(
            0,
            10,
            f"Page {self.page_no()} | Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
            align="C",
        )


@router.get("/{case_id}")
async def generate_report(
    case_id: str,
    current_user: UserContext = Depends(
        require_role("admin", "investigator", "auditor")
    ),
):
    safe_case_id = re.sub(r"[^a-zA-Z0-9-]", "_", case_id)

    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            require_case_access(conn, current_user, case_id)

            cur.execute("SELECT * FROM cases WHERE id = %s", (case_id,))
            case = cast(Any, cur.fetchone())
            if case:
                case = dict(case)
            if not case:
                raise HTTPException(status_code=404, detail="Case not found")

            cur.execute(
                """
                SELECT original_filename, sha256, byte_size, status, uploaded_at
                FROM evidence_files
                WHERE case_id = %s
                ORDER BY uploaded_at DESC
                """,
                (case_id,),
            )
            evidence_list = [dict(cast(Any, row)) for row in cur.fetchall()]

            cur.execute(
                """
                SELECT source, rule_or_model_id, severity, status, title, explanation, flow_reference, created_at
                FROM alerts
                WHERE case_id = %s
                ORDER BY created_at DESC
                """,
                (case_id,),
            )
            alerts_list = [dict(cast(Any, row)) for row in cur.fetchall()]

        def set_severity_color(pdf, severity: str):
            sev = severity.lower()
            if sev == "critical":
                pdf.set_text_color(185, 28, 28) # Red
            elif sev == "high":
                pdf.set_text_color(194, 65, 12) # Orange
            elif sev == "medium":
                pdf.set_text_color(180, 130, 0) # Dark Yellow
            else:
                pdf.set_text_color(29, 78, 216) # Blue

        pdf = ForensicReport()
        pdf.add_page()

        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, "Case Details", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 10)
        pdf.cell(0, 6, f"Case ID: {case['id']}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(
            0, 6, f"Case Number: {case['case_number']}", new_x="LMARGIN", new_y="NEXT"
        )
        pdf.cell(0, 6, f"Title: {case['title']}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(
            0,
            6,
            f"Description: {case.get('description') or 'No description provided.'}",
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.cell(
            0,
            6,
            f"Created At: {case['created_at'].strftime('%Y-%m-%d %H:%M:%S')} UTC",
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.ln(5)

        from app.core.audit import log_audit_event
        log_audit_event(
        conn,
        current_user,
        action="generate_report",
        target_type="case",
        target_id=case_id,
        case_id=case_id
        )

        pdf.set_font("helvetica", "B", 12)

        pdf.cell(0, 10, "Evidence Summary", new_x="LMARGIN", new_y="NEXT")
        if not evidence_list:
            pdf.set_font("helvetica", "I", 10)
            pdf.cell(
                0,
                6,
                "No evidence files have been registered for this case.",
                new_x="LMARGIN",
                new_y="NEXT",
            )
        else:
            for ev in evidence_list:
                pdf.set_font("helvetica", "B", 10)
                pdf.cell(
                    0,
                    6,
                    f"File: {ev['original_filename']}",
                    new_x="LMARGIN",
                    new_y="NEXT",
                )
                pdf.set_font("helvetica", "", 10)
                pdf.cell(
                    0, 6, f"SHA-256: {ev['sha256']}", new_x="LMARGIN", new_y="NEXT"
                )
                pdf.cell(
                    0,
                    6,
                    f"Size: {ev['byte_size']} bytes",
                    new_x="LMARGIN",
                    new_y="NEXT",
                )
                pdf.cell(0, 6, f"Status: {ev['status']}", new_x="LMARGIN", new_y="NEXT")
                pdf.cell(
                    0,
                    6,
                    f"Uploaded At: {ev['uploaded_at'].strftime('%Y-%m-%d %H:%M:%S')} UTC",
                    new_x="LMARGIN",
                    new_y="NEXT",
                )
                pdf.ln(2)

        pdf.ln(2)
 
        # Add Security Alerts & Model Analysis section
        pdf.add_page()
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, "Security Alerts & Model Analysis Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

        if not alerts_list:
            pdf.set_font("helvetica", "I", 10)
            pdf.cell(
                0,
                6,
                "No security alerts or anomaly detection indicators flagged for this case.",
                new_x="LMARGIN",
                new_y="NEXT",
            )
        else:
            ml_alerts = [a for a in alerts_list if a['source'].upper() == 'ML']
            sig_alerts = [a for a in alerts_list if a['source'].upper() != 'ML']

            pdf.set_font("helvetica", "B", 10)
            pdf.cell(0, 6, f"Total Flagged Threats: {len(alerts_list)} (ML Anomalies: {len(ml_alerts)}, Signature Matches: {len(sig_alerts)})", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

            pdf.set_font("helvetica", "B", 11)
            pdf.cell(0, 8, "Machine Learning Anomaly Analysis Logs (Latest 15)", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)

            if not ml_alerts:
                pdf.set_font("helvetica", "I", 9)
                pdf.cell(0, 6, "No machine learning anomalies detected in this case.", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)
            else:
                for idx, a in enumerate(ml_alerts[:15], 1):
                    pdf.set_font("helvetica", "B", 9)
                    set_severity_color(pdf, a['severity'])
                    pdf.multi_cell(0, 5, f"{idx}. Anomaly: {a['title']} ({a['severity'].upper()} Severity)", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_text_color(0, 0, 0)
                    pdf.set_font("helvetica", "", 9)
                    
                    expl = a['explanation']
                    if isinstance(expl, str):
                        try:
                            expl = json.loads(expl)
                        except:
                            pass
                    
                    reason = expl.get('reason', '') if isinstance(expl, dict) else str(expl)
                    confidence = expl.get('confidence', None) if isinstance(expl, dict) else None
                    score = expl.get('anomaly_score', None) if isinstance(expl, dict) else None
                    
                    pdf.multi_cell(0, 4.5, f"   Reason: {reason}", new_x="LMARGIN", new_y="NEXT")
                    if confidence is not None:
                        pdf.cell(0, 4.5, f"   Inference Confidence: {float(confidence)*100:.1f}%", new_x="LMARGIN", new_y="NEXT")
                    if score is not None:
                        pdf.cell(0, 4.5, f"   ML Decision Score: {score:.5f}", new_x="LMARGIN", new_y="NEXT")

                    flow = a['flow_reference']
                    if isinstance(flow, str):
                        try:
                            flow = json.loads(flow)
                        except:
                            pass
                    if isinstance(flow, dict):
                        proto = flow.get('protocol') or flow.get('proto') or 'N/A'
                        src_ip = flow.get('src_ip') or flow.get('srcIp') or 'N/A'
                        dst_ip = flow.get('dst_ip') or flow.get('dstIp') or 'N/A'
                        src_port = flow.get('src_port') or flow.get('srcPort') or 'N/A'
                        dst_port = flow.get('dst_port') or flow.get('dstPort') or 'N/A'
                        pdf.cell(0, 4.5, f"   Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto})", new_x="LMARGIN", new_y="NEXT")
                    
                    pdf.ln(2)

            pdf.ln(4)
            pdf.set_font("helvetica", "B", 11)
            pdf.cell(0, 8, "Signature Rules Engine Match Logs (Latest 15)", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)

            if not sig_alerts:
                pdf.set_font("helvetica", "I", 9)
                pdf.cell(0, 6, "No signature matches detected in this case.", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)
            else:
                for idx, a in enumerate(sig_alerts[:15], 1):
                    pdf.set_font("helvetica", "B", 9)
                    set_severity_color(pdf, a['severity'])
                    pdf.multi_cell(0, 5, f"{idx}. Alert: {a['title']} ({a['severity'].upper()} Severity) [{a['rule_or_model_id']}]", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_text_color(0, 0, 0)
                    pdf.set_font("helvetica", "", 9)
                    
                    expl = a['explanation']
                    if isinstance(expl, str):
                        try:
                            expl = json.loads(expl)
                        except:
                            pass
                    reason = expl.get('reason', '') if isinstance(expl, dict) else str(expl)
                    
                    pdf.multi_cell(0, 4.5, f"   Reason: {reason}", new_x="LMARGIN", new_y="NEXT")
                    flow = a['flow_reference']
                    if isinstance(flow, str):
                        try:
                            flow = json.loads(flow)
                        except:
                            pass
                    if isinstance(flow, dict):
                        proto = flow.get('protocol') or flow.get('proto') or 'N/A'
                        src_ip = flow.get('src_ip') or flow.get('srcIp') or 'N/A'
                        dst_ip = flow.get('dst_ip') or flow.get('dstIp') or 'N/A'
                        src_port = flow.get('src_port') or flow.get('srcPort') or 'N/A'
                        dst_port = flow.get('dst_port') or flow.get('dstPort') or 'N/A'
                        pdf.cell(0, 4.5, f"   Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto})", new_x="LMARGIN", new_y="NEXT")
                    
                    pdf.ln(2)

        pdf.ln(10)
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(0, 6, "Certification:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "I", 9)
        pdf.multi_cell(
            0,
            5,
            "I hereby certify that this report is a true and accurate representation of the digital evidence analyzed by the NetPack platform. The integrity of the original evidence has been maintained via cryptographic hashing.",
            new_x="LMARGIN",
            new_y="NEXT",
        )

        pdf_output = pdf.output()
        if isinstance(pdf_output, str):
            pdf_bytes = pdf_output.encode("latin-1")
        else:
            pdf_bytes = bytes(pdf_output)

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=NetPack_Report_{safe_case_id}.pdf"
            },
        )
    finally:
        if conn is not None:
            conn.close()
