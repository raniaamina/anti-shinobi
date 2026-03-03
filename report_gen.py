from fpdf import FPDF
from odf.opendocument import OpenDocumentSpreadsheet
from odf.table import Table, TableRow, TableCell
from odf.text import P
import datetime

class ReportGenerator:
    @staticmethod
    def export_pdf(results, filename, device_label="Unknown Device"):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt="Anti-Shinobi Spyware Scan Report", ln=True, align='C')
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(200, 10, txt=f"Device: {device_label}", ln=True, align='C')
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, txt=f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
        pdf.ln(10)

        for res in results:
            pdf.set_font("Arial", 'B', 12)
            color = (0, 200, 120) if res['score'] < 50 else (255, 75, 75)
            pdf.set_text_color(*color)
            pdf.cell(200, 10, txt=f"{res['package']} - Score: {res['score']}/100", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", size=10)
            for finding in res['findings']:
                pdf.cell(200, 8, txt=f"- {finding}", ln=True)
            pdf.ln(5)
        
        pdf.output(filename)
        return filename

    @staticmethod
    def export_ods(results, filename, device_label="Unknown Device"):
        doc = OpenDocumentSpreadsheet()
        table = Table(name="ScanResults")
        
        # Header Info Row
        info_row = TableRow()
        tc_info = TableCell()
        tc_info.addElement(P(text=f"Device: {device_label} | Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
        info_row.addElement(tc_info)
        table.addElement(info_row)
        
        table.addElement(TableRow()) # Spacer

        # Header Columns
        hr = TableRow()
        for h in ["Package", "Score", "Findings", "Third-Party"]:
            tc = TableCell()
            tc.addElement(P(text=h))
            hr.addElement(tc)
        table.addElement(hr)

        for res in results:
            tr = TableRow()
            
            p_cell = TableCell()
            p_cell.addElement(P(text=res['package']))
            tr.addElement(p_cell)
            
            s_cell = TableCell()
            s_cell.addElement(P(text=str(res['score'])))
            tr.addElement(s_cell)
            
            f_cell = TableCell()
            f_cell.addElement(P(text=", ".join(res['findings'])))
            tr.addElement(f_cell)

            tp_cell = TableCell()
            tp_cell.addElement(P(text="Yes" if res.get('is_third_party') else "No"))
            tr.addElement(tp_cell)
            
            table.addElement(tr)

        doc.spreadsheet.addElement(table)
        doc.save(filename)
        return filename
