import re
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

        pdf.ln(10)
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(0, 6, "Certification:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "I", 9)
        pdf.multi_cell(
            0,
            5,
            "I hereby certify that this report is a true and accurate representation of the digital evidence analyzed by the NetPack platform. The integrity of the original evidence has been maintained via cryptographic hashing.",
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
