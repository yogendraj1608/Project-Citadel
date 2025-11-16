import ssl
from email.message import EmailMessage
import smtplib

def send_alert(smtp_host, smtp_port, smtp_user, smtp_pass, recipients, rows):
    if not rows: return
    msg = EmailMessage()
    msg["Subject"] = f"[UEBA] {len(rows)} High/Critical login anomalies"
    msg["From"] = smtp_user
    msg["To"] = ", ".join(recipients)
    body = []
    for r in rows[:30]:
        body.append(f"{r['@timestamp']} user={r['user']} ip={r.get('source.ip')} host={r.get('host.name')} score={r.get('score'):.2f} why={r.get('why')}")
    msg.set_content("\n".join(body))
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx) as s:
        s.login(smtp_user, smtp_pass)
        s.send_message(msg)
