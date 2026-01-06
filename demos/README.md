# 🧪 Guía de Pruebas: AgentPay AI Buyer

Sigue estos pasos para ver a la IA comprando autónomamente en tu máquina local.

## 1. Requisitos Previos
Asegúrate de tener las Claves de API necesarias.
Crea un archivo `.env` en la carpeta raíz `agentpay_core/` (si no lo tienes) o asegúrate de tener estas variables en tu sistema:

```env
OPENAI_API_KEY=sk-proj-... (Tu clave real de OpenAI)
SUPABASE_URL=...
SUPABASE_KEY=...
```

## 2. Instalación
Instala las librerías de IA y navegación:

```bash
# Desde la carpeta agentpay_core
pip install -r requirements.txt
playwright install
```

## 3. Ejecución (Dos Terminales)

Necesitas dos ventanas de terminal abiertas.

### TERMINAL 1: El Vendedor Falso (FakeAmazon)
Este script simula ser la tienda online.
```bash
python demos/mock_vendor_server.py
```
*Verás que levanta en `http://127.0.0.1:9000`.*

### TERMINAL 2: El Agente (Cerebro IA)
Este script es AgentPay tomando el control.
```bash
python demos/run_ai_buyer.py
```

## ¿Qué va a pasar?
1. Se abrirá un navegador (chromium).
2. La IA irá a la tienda.
3. La IA leerá el formulario.
4. Verás en los logs: `🤖 [AI BRAIN] Decidí llamar a get_billing_info`.
5. La IA rellenará el "Magic Email" (`@inbound.agentpay.io`) automáticamente.
6. La compra se completará.

## Solución de Problemas
- **Error "OpenAI API Key missing"**: Asegúrate de exportar la variable `set OPENAI_API_KEY=sk-...` en Windows o usar el archivo .env.
- **Error de importación**: Ejecuta siempre los scripts desde `agentpay_core` (la carpeta raíz), no desde dentro de `demos/`.
  - BIEN: `python demos/run_ai_buyer.py`
  - MAL: `cd demos` -> `python run_ai_buyer.py`
