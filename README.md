# Network Monitoring System (NMS)

A comprehensive network monitoring solution built with Django and React, designed specifically for ISPs and network administrators.

## 🚀 Features

### ✅ **Implemented Features**

**Core Infrastructure:**
- 🔐 JWT-based authentication with role-based access control (RBAC)
- 👥 Multi-role support (SuperAdmin, Admin, Editor, Viewer)
- 📊 Comprehensive audit logging system
- 📁 Data import/export (Excel, CSV, JSON, PDF)
- 🏢 Location and device group management

**Monitoring System:**
- 🏓 ICMP/Ping monitoring with configurable thresholds
- ⚠️ Advanced alerting system with threshold management
- 📈 Real-time status tracking and history
- 🎯 Per-host and per-group threshold configuration

**Notification System:**
- 📧 Email notifications (SMTP)
- 📱 Telegram bot integration
- 💬 Slack webhook support
- 🏢 Microsoft Teams integration
- 📲 SMS notifications (Twilio)
- 🔄 Multi-channel escalation system

**Data Management:**
- 🏠 Host/device management with ISP-specific fields
- 📍 Location hierarchy support
- 👥 Device grouping and categorization
- 🔄 Bulk operations and data validation

### 🚧 **In Development**
- SNMP monitoring system
- Celery task scheduling
- React frontend dashboard
- Network auto-discovery
- Grafana integration

## 🛠️ Technology Stack

**Backend:**
- Django 5.1+ with Python 3.12+
- Django REST Framework
- PostgreSQL/SQLite database
- Redis for caching and task queue
- Celery for background tasks

**Frontend (Planned):**
- React 19 with TypeScript
- Redux Toolkit for state management
- Tailwind CSS for styling
- Vite for build tooling

**Monitoring Stack:**
- Prometheus for metrics collection
- Grafana for visualization
- Custom monitoring agents

## 📋 Prerequisites

- Python 3.12+
- Node.js 18+ (for frontend)
- PostgreSQL 13+ (or SQLite for development)
- Redis 6+

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/network-monitoring-system.git
cd network-monitoring-system
```

### 2. Set Up Python Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your configuration
nano .env
```

### 4. Set Up Database

```bash
# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Load sample data (optional)
python manage.py loaddata fixtures/sample_data.json
```

### 5. Start Development Server

```bash
# Start Django development server
python manage.py runserver

# In another terminal, start Celery worker (optional)
celery -A nms worker -l info

# Start Celery beat scheduler (optional)
celery -A nms beat -l info
```

### 6. Access the Application

- **Admin Interface:** http://localhost:8000/admin/
- **API Documentation:** http://localhost:8000/api/
- **Frontend:** http://localhost:3000/ (when implemented)

## 📧 Setting Up Notifications

### Email Notifications

Update your `.env` file:

```env
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=nms@yourcompany.com
```

### Telegram Notifications

1. Create a Telegram bot:
   ```bash
   python setup_telegram_bot.py
   ```

2. Follow the interactive setup to get your bot token and chat ID

3. Test notifications:
   ```bash
   python manage.py test_notifications --channel telegram --recipient YOUR_CHAT_ID
   ```

### Test All Notifications

```bash
# List channel status
python manage.py test_notifications --list-channels

# Test all configured channels
python manage.py test_notifications

# Create test alert and send notifications
python manage.py test_notifications --create-alert
```

## 🐳 Docker Setup

```bash
# Build and start all services
docker-compose up -d

# Run migrations
docker-compose exec web python manage.py migrate

# Create superuser
docker-compose exec web python manage.py createsuperuser
```

## 📊 Monitoring Configuration

### Adding Hosts

```python
# Via Django shell
python manage.py shell

from monitoring.models import Host, Location, DeviceGroup

# Create location
location = Location.objects.create(name="Main Office", address="123 Main St")

# Create device group
group = DeviceGroup.objects.create(name="Routers", description="Core routers")

# Add host
host = Host.objects.create(
    hostname="router-01",
    ip_address="192.168.1.1",
    device_type="router",
    location=location,
    group=group,
    ping_enabled=True,
    ping_warning_latency=100.0,
    ping_critical_latency=500.0
)
```

### Via API

```bash
# Get authentication token
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}'

# Add host
curl -X POST http://localhost:8000/api/hosts/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "router-01",
    "ip_address": "192.168.1.1",
    "device_type": "router",
    "location": "location-uuid",
    "group": "group-uuid"
  }'
```

## 🧪 Testing

```bash
# Run all tests
python manage.py test

# Run specific test module
python manage.py test monitoring.tests

# Run with coverage
coverage run --source='.' manage.py test
coverage report
coverage html
```

## 📁 Project Structure

```
network-monitoring-system/
├── .kiro/specs/                 # Feature specifications
├── api/                         # API app
├── core/                        # Core functionality
├── monitoring/                  # Monitoring system
├── frontend/                    # React frontend (planned)
├── docker/                      # Docker configurations
├── logs/                        # Application logs
├── static/                      # Static files
├── templates/                   # Django templates
├── tests/                       # Test files
├── manage.py                    # Django management script
├── requirements.txt             # Python dependencies
├── docker-compose.yml           # Docker compose configuration
└── README.md                    # This file
```

## 🔧 Configuration

### Environment Variables

Key environment variables in `.env`:

```env
# Django
SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/nms_db

# Redis
REDIS_URL=redis://localhost:6379/0

# Email
EMAIL_HOST=smtp.gmail.com
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# Telegram
TELEGRAM_NOTIFICATIONS_ENABLED=True
TELEGRAM_BOT_TOKEN=your-bot-token

# Monitoring
MONITORING_INTERVAL=30
ALERT_ESCALATION_INTERVAL=30
```

## 🚀 Deployment

### Production Checklist

- [ ] Set `DEBUG=False` in production
- [ ] Configure proper database (PostgreSQL)
- [ ] Set up Redis for caching and task queue
- [ ] Configure web server (Nginx + Gunicorn)
- [ ] Set up SSL certificates
- [ ] Configure monitoring and logging
- [ ] Set up backup procedures
- [ ] Configure firewall rules

### Docker Production

```bash
# Use production docker-compose
docker-compose -f docker-compose.prod.yml up -d
```

## 📈 Roadmap

### Phase 1 (Current)
- ✅ Core infrastructure and authentication
- ✅ Basic monitoring (ping/ICMP)
- ✅ Alert system and notifications
- 🚧 SNMP monitoring
- 🚧 Task scheduling system

### Phase 2 (Next)
- 🔲 React frontend dashboard
- 🔲 Network auto-discovery
- 🔲 Grafana integration
- 🔲 Advanced reporting

### Phase 3 (Future)
- 🔲 Mobile PWA
- 🔲 Machine learning for anomaly detection
- 🔲 Configuration management
- 🔲 Network topology visualization

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📧 Email: support@yourcompany.com
- 📖 Documentation: [Wiki](https://github.com/yourusername/network-monitoring-system/wiki)
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/network-monitoring-system/issues)

## 🙏 Acknowledgments

- Django and Django REST Framework communities
- React and TypeScript communities
- All contributors and testers

---

**Built with ❤️ for network administrators and ISPs**