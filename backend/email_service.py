import smtplib
import os
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

GMAIL_USER     = os.getenv("GMAIL_USER", "")
GMAIL_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "")

def generate_otp(length=6) -> str:
    return ''.join(random.choices(string.digits, k=length))

def generate_reset_token(length=32) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def send_email(to_email: str, subject: str, html_body: str) -> bool:
    if not GMAIL_USER or not GMAIL_PASSWORD:
        print("⚠️ Gmail credentials not set — email not sent")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"PhishGuard <{GMAIL_USER}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_USER, GMAIL_PASSWORD)
            server.sendmail(GMAIL_USER, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"❌ Email error: {e}")
        return False

def send_otp_email(to_email: str, name: str, otp: str) -> bool:
    subject = "PhishGuard — Your OTP Verification Code"
    html = f"""
    <!DOCTYPE html>
    <html>
    <body style="margin:0;padding:0;background:#05080f;font-family:'Segoe UI',sans-serif;">
      <div style="max-width:480px;margin:40px auto;background:#090e1a;border:1px solid rgba(0,200,255,0.15);border-radius:16px;overflow:hidden;">
        <div style="background:linear-gradient(135deg,#0a1a3a,#0d2555);padding:28px 32px;border-bottom:1px solid rgba(0,200,255,0.15);">
          <div style="display:flex;align-items:center;gap:12px;">
            <div style="font-size:28px;">🛡️</div>
            <div>
              <div style="color:#deeaf8;font-size:20px;font-weight:700;letter-spacing:1px;">PhishGuard</div>
              <div style="color:#00c8ff;font-size:11px;letter-spacing:2px;margin-top:2px;">URL THREAT DETECTION</div>
            </div>
          </div>
        </div>
        <div style="padding:32px;">
          <p style="color:#6e93b8;font-size:14px;margin:0 0 8px;">Hi <strong style="color:#deeaf8;">{name}</strong>,</p>
          <p style="color:#6e93b8;font-size:14px;margin:0 0 24px;">Your OTP verification code is:</p>
          <div style="background:#0d1525;border:1px solid rgba(0,200,255,0.25);border-radius:12px;padding:20px;text-align:center;margin-bottom:24px;">
            <div style="font-size:36px;font-weight:700;letter-spacing:12px;color:#00c8ff;font-family:monospace;">{otp}</div>
            <div style="color:#2e4a66;font-size:11px;margin-top:8px;">Valid for 10 minutes</div>
          </div>
          <p style="color:#2e4a66;font-size:12px;margin:0;">If you didn't request this, please ignore this email. Your account is safe.</p>
        </div>
        <div style="padding:16px 32px;border-top:1px solid rgba(0,200,255,0.08);text-align:center;">
          <p style="color:#2e4a66;font-size:11px;margin:0;">© 2026 PhishGuard · Final Year Project — Divyansh Sharma</p>
        </div>
      </div>
    </body>
    </html>
    """
    return send_email(to_email, subject, html)

def send_reset_email(to_email: str, name: str, reset_token: str, base_url: str) -> bool:
    reset_link = f"{base_url}/reset-password?token={reset_token}"
    subject    = "PhishGuard — Password Reset Request"
    html = f"""
    <!DOCTYPE html>
    <html>
    <body style="margin:0;padding:0;background:#05080f;font-family:'Segoe UI',sans-serif;">
      <div style="max-width:480px;margin:40px auto;background:#090e1a;border:1px solid rgba(0,200,255,0.15);border-radius:16px;overflow:hidden;">
        <div style="background:linear-gradient(135deg,#0a1a3a,#0d2555);padding:28px 32px;border-bottom:1px solid rgba(0,200,255,0.15);">
          <div style="display:flex;align-items:center;gap:12px;">
            <div style="font-size:28px;">🛡️</div>
            <div>
              <div style="color:#deeaf8;font-size:20px;font-weight:700;letter-spacing:1px;">PhishGuard</div>
              <div style="color:#00c8ff;font-size:11px;letter-spacing:2px;margin-top:2px;">PASSWORD RESET</div>
            </div>
          </div>
        </div>
        <div style="padding:32px;">
          <p style="color:#6e93b8;font-size:14px;margin:0 0 8px;">Hi <strong style="color:#deeaf8;">{name}</strong>,</p>
          <p style="color:#6e93b8;font-size:14px;margin:0 0 24px;">We received a request to reset your password. Click the button below:</p>
          <div style="text-align:center;margin:28px 0;">
            <a href="{reset_link}" style="display:inline-block;background:#00c8ff;color:#fff;text-decoration:none;padding:14px 32px;border-radius:10px;font-weight:700;font-size:14px;letter-spacing:1px;">Reset Password</a>
          </div>
          <p style="color:#2e4a66;font-size:12px;margin:0 0 8px;">Or copy this link:</p>
          <div style="background:#0d1525;border:1px solid rgba(0,200,255,0.15);border-radius:8px;padding:12px;word-break:break-all;">
            <a href="{reset_link}" style="color:#00c8ff;font-size:11px;font-family:monospace;">{reset_link}</a>
          </div>
          <p style="color:#2e4a66;font-size:12px;margin:20px 0 0;">This link expires in <strong>30 minutes</strong>. If you didn't request this, ignore this email.</p>
        </div>
        <div style="padding:16px 32px;border-top:1px solid rgba(0,200,255,0.08);text-align:center;">
          <p style="color:#2e4a66;font-size:11px;margin:0;">© 2026 PhishGuard · Final Year Project — Divyansh Sharma</p>
        </div>
      </div>
    </body>
    </html>
    """
    return send_email(to_email, subject, html)

def send_welcome_email(to_email: str, name: str) -> bool:
    subject = "Welcome to PhishGuard! 🛡️"
    html = f"""
    <!DOCTYPE html>
    <html>
    <body style="margin:0;padding:0;background:#05080f;font-family:'Segoe UI',sans-serif;">
      <div style="max-width:480px;margin:40px auto;background:#090e1a;border:1px solid rgba(0,200,255,0.15);border-radius:16px;overflow:hidden;">
        <div style="background:linear-gradient(135deg,#0a1a3a,#0d2555);padding:28px 32px;border-bottom:1px solid rgba(0,200,255,0.15);">
          <div style="font-size:28px;margin-bottom:8px;">🛡️</div>
          <div style="color:#deeaf8;font-size:20px;font-weight:700;">Welcome to PhishGuard!</div>
        </div>
        <div style="padding:32px;">
          <p style="color:#6e93b8;font-size:14px;margin:0 0 16px;">Hi <strong style="color:#deeaf8;">{name}</strong>, your account is ready! 🎉</p>
          <div style="background:#0d1525;border:1px solid rgba(0,230,118,0.2);border-radius:10px;padding:16px;margin-bottom:20px;">
            <div style="color:#00e676;font-size:13px;font-weight:700;margin-bottom:8px;">✅ Account Created Successfully</div>
            <div style="color:#6e93b8;font-size:12px;">Email: <span style="color:#deeaf8;">{to_email}</span></div>
          </div>
          <p style="color:#6e93b8;font-size:13px;margin:0;">Start scanning URLs for phishing threats at <a href="https://phishguard-app-six.vercel.app" style="color:#00c8ff;">phishguard-app-six.vercel.app</a></p>
        </div>
        <div style="padding:16px 32px;border-top:1px solid rgba(0,200,255,0.08);text-align:center;">
          <p style="color:#2e4a66;font-size:11px;margin:0;">© 2026 PhishGuard · Final Year Project — Divyansh Sharma</p>
        </div>
      </div>
    </body>
    </html>
    """
    return send_email(to_email, subject, html)