import os

EMAIL_ENABLED = False
EMAIL_SENDER = os.environ.get('EMAIL_SENDER', '')
EMAIL_RECEIVER = os.environ.get('EMAIL_RECEIVER', '')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')
EMAIL_SMTP = os.environ.get('EMAIL_SMTP', 'smtp.gmail.com')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', '587'))
