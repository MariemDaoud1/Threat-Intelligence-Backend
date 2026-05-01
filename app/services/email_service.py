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

    @staticmethod
    def send_contributor_welcome_email(to_email: str, organisation_name: str, temporary_password: str) -> None:
        if not settings.SMTP_ENABLED:
            raise RuntimeError("SMTP is disabled. Enable SMTP_ENABLED to send contributor onboarding emails.")

        msg = EmailMessage()
        msg["Subject"] = "Your Contributor Account"
        msg["From"] = settings.SMTP_FROM_EMAIL
        msg["To"] = to_email
        msg.set_content(
            "Hello,\n\n"
            f"Your contributor account for organisation '{organisation_name}' is ready.\n\n"
            f"Temporary password: {temporary_password}\n\n"
            "You must change this password at first login.\n"
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

    @staticmethod
    def send_rejection_email(to_email: str, organisation_name: str, reason: str | None = None) -> None:
        if not settings.SMTP_ENABLED:
            raise RuntimeError("SMTP is disabled. Enable SMTP_ENABLED to send rejection emails.")

        msg = EmailMessage()
        msg["Subject"] = "Organisation Registration Update"
        msg["From"] = settings.SMTP_FROM_EMAIL
        msg["To"] = to_email
        body = (
            "Hello,\n\n"
            f"Your organisation '{organisation_name}' registration request has been rejected.\n"
        )
        if reason:
            body += f"Reason: {reason}\n"
        msg.set_content(body)

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
