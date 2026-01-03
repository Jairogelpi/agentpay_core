from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from loguru import logger
import os
import datetime

def generate_invoice_pdf(transaction_id, agent_id, vendor, amount, description, tax_id="EU-VAT-PENDING", invoice_type="INVOICE"):
    is_refund = invoice_type == "CREDIT_NOTE" or amount < 0
    display_amount = abs(amount)
    doc_title = "CREDIT NOTE / RECTIFICATIVA" if is_refund else "AGENTPAY - FACTURA OFICIAL"
    
    filename = f"{'credit_note' if is_refund else 'invoice'}_{transaction_id}.pdf"
    path = os.path.join("invoices", filename)
    
    # Asegurar que el directorio existe
    if not os.path.exists("invoices"):
        os.makedirs("invoices")
        
    c = canvas.Canvas(path, pagesize=letter)
    width, height = letter
    
    # Datos Legales del Emisor (AgentPay LLC/SL)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 50, "AGENTPAY GLOBAL SERVICES")
    c.setFont("Helvetica", 10)
    c.drawString(50, height - 65, "Tax ID: US-EIN-123456789 / EU-VAT-ES12345678")
    c.drawString(50, height - 75, "Address: Gran Via 1, Madrid, ES / Delaware, USA")

    # Datos de la Factura
    c.setFont("Helvetica-Bold", 12)
    c.drawString(400, height - 50, f"{'REFUND' if is_refund else 'INVOICE'} #: {transaction_id[:8].upper()}")
    c.drawString(400, height - 65, f"DATE: {datetime.datetime.now().strftime('%Y-%m-%d')}")

    # Cuerpo de la Factura
    c.setFont("Helvetica-Bold", 20)
    c.drawString(50, height - 100, doc_title) # Título Dinámico

    c.setFont("Helvetica", 12)
    c.line(50, height - 120, width - 50, height - 120)
    c.drawString(50, height - 140, f"BILL TO: Agent {agent_id}")
    c.drawString(50, height - 155, f"VENDOR: {vendor}")
    c.drawString(50, height - 170, f"DESCRIPTION: {description}")

    # Desglose Contable (REQUISITO LEGAL)
    tax_rate = 0.21 # Ejemplo IVA España
    net_amount = display_amount / (1 + tax_rate)
    tax_amount = display_amount - net_amount

    # Si es Nota de Crédito, mostramos valores negativos visualmente
    sign = "-" if is_refund else ""

    c.line(350, height - 200, width - 50, height - 200)
    c.drawString(350, height - 220, f"Subtotal (Net): {sign}${net_amount:.2f}")
    c.drawString(350, height - 235, f"Tax (VAT 21%): {sign}${tax_amount:.2f}")
    c.setFont("Helvetica-Bold", 14)
    c.drawString(350, height - 260, f"TOTAL: {sign}${display_amount:.2f}")

    c.setFont("Helvetica-Oblique", 8)
    c.drawString(50, 50, "Este documento tiene validez legal como justificante de gasto B2B.")
    
    c.save()
    logger.info(f"📄 DOCUMENTO GENERADO: {path}")
    return path # En producción devolveríamos una URL S3
