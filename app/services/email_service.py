import smtplib
from email.message import EmailMessage

from app.config import settings


class EmailService:
    @staticmethod
    def send_api_key_email(to_email: str, organisation_name: str, api_key: str) -> None:
        if not settings.SMTP_ENABLED:
            raise RuntimeError("SMTP is disabled. Enable SMTP_ENABLED to send API keys by email.")

        msg = EmailMessage()
        msg["Subject"] = "Your Threat Intel API Key"
        msg["From"] = settings.SMTP_FROM_EMAIL
        msg["To"] = to_email
        msg.set_content(
            "Hello,\n\n"
            f"Here is the API key for organisation '{organisation_name}':\n\n"
            f"{api_key}\n\n"
            "Store this key in a secure secret manager. "
            "For security reasons, this key is only sent once and cannot be retrieved later.\n"
        )

        if settings.SMTP_USE_SSL:
            with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT) as smtp:
                if settings.SMTP_USERNAME:
                    smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                smtp.send_message(msg)
            return

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as smtp:
            if settings.SMTP_STARTTLS:
                smtp.starttls()
            if settings.SMTP_USERNAME:
                smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            smtp.send_message(msg)
