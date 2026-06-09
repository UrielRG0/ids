		#[15]
import smtplib
import sys
from email.message import EmailMessage

if len(sys.argv) < 3:
    print("Error: Faltan argumentos. Uso: python correo.py 'Asunto' 'Mensaje'")
    sys.exit(1)

asunto = sys.argv[1]
cuerpo = sys.argv[2]
			#[16]
env = {}
try:
    with open('.env', 'r') as file:
        for line in file:
            line = line.strip()
            # Ignorar líneas vacías o comentarios
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                env[key] = value
except FileNotFoundError:
    print("Error: No se encontró el archivo .env")
    sys.exit(1)

			#[17]
msg = EmailMessage()
msg.set_content(cuerpo)
msg['Subject'] = f"ALERTA IDS: {asunto}"
msg['From'] = env.get('SMTP_USER')
msg['To'] = env.get('ADMIN_EMAIL')

try:
    print(f"Conectando a {env.get('SMTP_SERVER')}...")
    server = smtplib.SMTP(env.get('SMTP_SERVER'), int(env.get('SMTP_PORT')))
    server.starttls() # Esto encripta la conexión (Seguridad)
    server.login(env.get('SMTP_USER'), env.get('SMTP_PASS'))
    server.send_message(msg)
    server.quit()
except Exception as e:
    print(f"Error al enviar el correo: {e}")
