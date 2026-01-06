
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, FileResponse
import uvicorn
import os

app = FastAPI()

# --- FAKE DATABASE ---
orders = []

HTML_CHECKOUT = """
<!DOCTYPE html>
<html>
<head>
    <title>FakeAmazon - Checkout</title>
    <style>
        body { font-family: sans-serif; padding: 40px; }
        .box { border: 1px solid #ccc; padding: 20px; border-radius: 8px; max-width: 400px; }
        input { width: 100%; padding: 8px; margin: 10px 0; }
        button { background: #ff9900; color: white; padding: 10px; width: 100%; border: none; font-weight: bold; cursor: pointer; }
        .label { font-weight: bold; font-size: 12px; color: #555; }
    </style>
</head>
<body>
    <h1>🛒 FakeAmazon Checkout</h1>
    <div class="box">
        <h3>Order Summary: Dell PowerEdge Server ($1,200.00)</h3>
        <hr>
        <form action="/buy" method="post">
            <div class="label">Billing Name</div>
            <input type="text" name="name" placeholder="John Doe" required>
            
            <div class="label">Billing Email (Where to send invoice?)</div>
            <input type="email" name="email" placeholder="john@gmail.com" required>
            
            <div class="label">Address</div>
            <input type="text" name="address" placeholder="123 Main St" required>
            
            <button type="submit">Place Order</button>
        </form>
    </div>
</body>
</html>
"""

HTML_SUCCESS = """
<!DOCTYPE html>
<html>
<head><title>Order Placed</title></head>
<body>
    <h1 style="color: green;">✅ Order Placed Successfully!</h1>
    <p>We have sent the receipt to: <b>{email}</b></p>
    <p><a href="/orders">View My Orders</a></p>
</body>
</html>
"""

HTML_ORDERS = """
<!DOCTYPE html>
<html>
<head>
    <title>My Orders</title>
    <style>
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>📦 My Orders (History)</h1>
    <table>
        <tr>
            <th>Order ID</th>
            <th>Item</th>
            <th>Amount</th>
            <th>Action</th>
        </tr>
        <!-- ROWS_HERE -->
    </table>
</body>
</html>
"""

@app.get("/checkout", response_class=HTMLResponse)
async def checkout_page():
    return HTML_CHECKOUT

@app.post("/buy", response_class=HTMLResponse)
async def buy_item(name: str = Form(...), email: str = Form(...), address: str = Form(...)):
    print(f"\n[MERCHANT] 💰 New Order Placed by {name}!")
    print(f"[MERCHANT] 📧 Sending Invoice to: {email}")
    
    # SAVE ORDER TO MEMORY
    import random
    order_id = f"ORD-{random.randint(10000,99999)}"
    new_order = {
        "id": order_id,
        "item": "Dell PowerEdge Server",
        "amount": "$1,200.00",
        "date": "2026-01-06",
        "email": email
    }
    orders.append(new_order)
    
    # Simular lógica del backend del vendedor
    if "inbound.agentpay.io" in email:
        print("[MERCHANT] ✅ DETECTED: Corporate Agent Email. Invoice will be processed automatically by AgentPay.")
    else:
        print("[MERCHANT] ⚠️ WARNING: Personal email detected. Invoice might be lost in user inbox.")

    return HTML_SUCCESS.format(email=email)

@app.get("/orders", response_class=HTMLResponse)
async def orders_page():
    # Build dynamic table
    rows = ""
    for o in orders:
        rows += f"""
        <tr>
            <td>{o['id']}</td>
            <td>{o['item']}</td>
            <td>{o['amount']}</td>
            <td><a href="/download/invoice">⬇️ Download Invoice PDF</a></td>
        </tr>
        """
    
    dynamic_html = HTML_ORDERS.replace("<!-- ROWS_HERE -->", rows)
    return HTMLResponse(content=dynamic_html)

@app.get("/download/invoice")
async def download_invoice():
    # Retorna un PDF dummy
    content = b"%PDF-1.4 ... (Fake Invoice Content) ..."
    from fastapi.responses import Response
    return Response(content=content, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=invoice_123.pdf"})

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9000)
