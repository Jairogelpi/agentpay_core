from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from loguru import logger
import os
import datetime

def generate_invoice_pdf(transaction_id, agent_id, vendor, amount, description):
    """
    Genera una factura PDF simple para una transacción aprobada.
    """
    filename = f"invoice_{transaction_id}.pdf"
    path = os.path.join("invoices", filename)
    
    # Asegurar que el directorio existe
    if not os.path.exists("invoices"):
        os.makedirs("invoices")
        
    c = canvas.Canvas(path, pagesize=letter)
    width, height = letter
    
    # Cabecera
    c.setFont("Helvetica-Bold", 20)
    c.drawString(50, height - 50, "AGENTPAY - FACTURA OFICIAL")
    
    c.setFont("Helvetica", 12)
    c.drawString(50, height - 80, f"Fecha: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    c.drawString(50, height - 100, f"ID Transacción: {transaction_id}")
    
    # Detalles
    c.line(50, height - 120, width - 50, height - 120)
    
    c.drawString(50, height - 150, f"Agente: {agent_id}")
    c.drawString(50, height - 170, f"Proveedor: {vendor}")
    c.drawString(50, height - 190, f"Descripción: {description}")
    
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 230, f"TOTAL PAGADO: ${amount:.2f}")
    
    c.setFont("Helvetica-Oblique", 10)
    c.drawString(50, 50, "Generado automáticamente por AgentPay Core System.")
    
    c.save()
    logger.info(f"📄 FACTURA GENERADA: {path}")
    return path # En producción devolveríamos una URL S3
