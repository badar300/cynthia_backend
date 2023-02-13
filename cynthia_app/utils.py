from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode


def send_reset_email(email, user):
    subject = 'Account Settings'
    message = f'http://localhost:5173/reset_password'
    to_email = email
    email = EmailMessage(subject, message, to=[to_email])
    email.send()
    return 1, "email has been send"
