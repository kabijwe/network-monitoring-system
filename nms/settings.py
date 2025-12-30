"""
Django settings for Network Monitoring System (NMS).

This configuration supports both development and production environments
with proper security, performance, and monitoring capabilities.
"""

import os
from pathlib import Path
from decouple import config, Csv
import dj_database_url

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY', default='django-insecure-change-me-in-production')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config('DEBUG', default=True, cast=bool)

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1,0.0.0.0', cast=Csv())

# Application definition
DJANGO_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

THIRD_PARTY_APPS = [
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'channels',
    'django_celery_beat',
    'django_celery_results',
    'django_prometheus',
    'django_otp',
]

LOCAL_APPS = [
    'core',
    'monitoring',
    'api',
    'frontend',
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    'django_prometheus.middleware.PrometheusBeforeMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'core.csrf_middleware.APICSRFExemptMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_otp.middleware.OTPMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'core.middleware.AuditMiddleware',
    'django_prometheus.middleware.PrometheusAfterMiddleware',
]

# CORS Configuration
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:8001",
    "http://127.0.0.1:8001",
]

CORS_ALLOW_CREDENTIALS = True

# CSRF Configuration
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:8001",
    "http://127.0.0.1:8001",
]

# Exempt API endpoints from CSRF
CSRF_EXEMPT_URLS = [
    r'^/api/',
]

ROOT_URLCONF = 'nms.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'nms.wsgi.application'
ASGI_APPLICATION = 'nms.asgi.application'

# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases
DATABASES = {
    'default': dj_database_url.config(
        default=config('DATABASE_URL', default='sqlite:///db.sqlite3'),
        conn_max_age=600,
        conn_health_checks=True,
    )
}

# Redis Configuration
REDIS_URL = config('REDIS_URL', default='redis://localhost:6379/0')

# Channels Configuration
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [REDIS_URL],
        },
    },
}

# Celery Configuration
CELERY_BROKER_URL = config('CELERY_BROKER_URL', default=REDIS_URL)
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND', default=REDIS_URL)
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

# Cache Configuration
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': REDIS_URL,
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Custom User Model
AUTH_USER_MODEL = 'core.User'

# Django REST Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 50,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
}

# JWT Configuration
from datetime import timedelta
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
}

# CORS Configuration
CORS_ALLOWED_ORIGINS = config(
    'CORS_ALLOWED_ORIGINS',
    default='http://localhost:3000,http://127.0.0.1:3000',
    cast=Csv()
)
CORS_ALLOW_CREDENTIALS = True

# Security Settings
if not DEBUG:
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_REDIRECT_EXEMPT = []
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    X_FRAME_OPTIONS = 'DENY'

# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'nms.log',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'DEBUG' if DEBUG else 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'nms': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
    },
}

# Monitoring Configuration
MONITORING_SETTINGS = {
    'PING_TIMEOUT': 5,  # seconds
    'SNMP_TIMEOUT': 10,  # seconds
    'MONITORING_INTERVAL': 30,  # seconds
    'MAX_CONCURRENT_CHECKS': 100,
    'ALERT_COOLDOWN': 300,  # seconds
}

# Notification Settings
NOTIFICATION_SETTINGS = {
    # Email configuration
    'email': {
        'enabled': config('EMAIL_NOTIFICATIONS_ENABLED', default=True, cast=bool),
        'smtp_host': config('EMAIL_HOST', default='localhost'),
        'smtp_port': config('EMAIL_PORT', default=587, cast=int),
        'smtp_use_tls': config('EMAIL_USE_TLS', default=True, cast=bool),
        'smtp_username': config('EMAIL_HOST_USER', default=''),
        'smtp_password': config('EMAIL_HOST_PASSWORD', default=''),
        'from_email': config('DEFAULT_FROM_EMAIL', default='nms@example.com'),
        'from_name': config('EMAIL_FROM_NAME', default='Network Monitoring System'),
    },
    
    # Telegram configuration
    'telegram': {
        'enabled': config('TELEGRAM_NOTIFICATIONS_ENABLED', default=False, cast=bool),
        'bot_token': config('TELEGRAM_BOT_TOKEN', default=''),
    },
    
    # Slack configuration
    'slack': {
        'enabled': config('SLACK_NOTIFICATIONS_ENABLED', default=False, cast=bool),
        'webhook_url': config('SLACK_WEBHOOK_URL', default=''),
        'channel': config('SLACK_DEFAULT_CHANNEL', default='#alerts'),
        'username': config('SLACK_BOT_USERNAME', default='NMS Bot'),
        'icon_emoji': config('SLACK_BOT_ICON', default=':warning:'),
    },
    
    # Microsoft Teams configuration
    'teams': {
        'enabled': config('TEAMS_NOTIFICATIONS_ENABLED', default=False, cast=bool),
        'webhook_url': config('TEAMS_WEBHOOK_URL', default=''),
    },
    
    # SMS configuration (Twilio)
    'sms': {
        'enabled': config('SMS_NOTIFICATIONS_ENABLED', default=False, cast=bool),
        'account_sid': config('TWILIO_ACCOUNT_SID', default=''),
        'auth_token': config('TWILIO_AUTH_TOKEN', default=''),
        'from_number': config('TWILIO_PHONE_NUMBER', default=''),
    },
}

# Alert System Settings
ALERT_SETTINGS = {
    'ESCALATION_INTERVAL_MINUTES': config('ALERT_ESCALATION_INTERVAL', default=30, cast=int),
    'MAX_ESCALATION_LEVEL': config('ALERT_MAX_ESCALATION_LEVEL', default=3, cast=int),
    'AUTO_RESOLVE_TIMEOUT_HOURS': config('ALERT_AUTO_RESOLVE_TIMEOUT', default=24, cast=int),
    'DUPLICATE_ALERT_WINDOW_MINUTES': config('ALERT_DUPLICATE_WINDOW', default=5, cast=int),
    'SUPPRESS_DURING_MAINTENANCE': config('ALERT_SUPPRESS_MAINTENANCE', default=True, cast=bool),
    'SUPPRESS_ACKNOWLEDGED_ALERTS': config('ALERT_SUPPRESS_ACKNOWLEDGED', default=True, cast=bool),
}

# Create logs directory if it doesn't exist
os.makedirs(BASE_DIR / 'logs', exist_ok=True)