#!/usr/bin/env python3
"""
Simple script to test the notification system.
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nms.settings')
django.setup()

from monitoring.notification_service import get_notification_status, test_notification_channel


def main():
    print("Network Monitoring System - Notification Test")
    print("=" * 50)
    
    # Check notification status
    print("\n1. Checking notification channel status...")
    try:
        status = get_notification_status()
        
        for channel, info in status.items():
            enabled = info['enabled']
            configured = info['configured']
            status_text = "✅ Ready" if enabled and configured else "❌ Not Ready"
            
            print(f"   {channel.upper():<12}: {status_text}")
            if not enabled:
                print(f"                 - Not enabled")
            if not configured:
                print(f"                 - Not configured")
    
    except Exception as e:
        print(f"   Error checking status: {e}")
    
    # Test email notification
    print("\n2. Testing email notification...")
    try:
        success = test_notification_channel('email', 'bikram.niroula@worldlink.com.np')
        if success:
            print("   ✅ Email test successful")
        else:
            print("   ❌ Email test failed (check SMTP configuration)")
    except Exception as e:
        print(f"   ❌ Email test error: {e}")
    
    # Test Telegram notification (if configured)
    print("\n3. Testing Telegram notification...")
    
    # Check if Telegram is configured
    from django.conf import settings
    telegram_config = settings.NOTIFICATION_SETTINGS.get('telegram', {})
    
    if telegram_config.get('enabled') and telegram_config.get('bot_token'):
        try:
            # Use the phone number as chat ID for now
            success = test_notification_channel('telegram', '9842478259')
            if success:
                print("   ✅ Telegram test successful")
            else:
                print("   ❌ Telegram test failed")
        except Exception as e:
            print(f"   ❌ Telegram test error: {e}")
    else:
        print("   ⚠️  Telegram not configured")
        print("   Run: python setup_telegram_bot.py")
    
    print("\n" + "=" * 50)
    print("Test complete!")
    
    if telegram_config.get('enabled'):
        print("\nTo create a test alert and send notifications:")
        print("python manage.py test_notifications --create-alert")
    else:
        print("\nTo set up Telegram notifications:")
        print("python setup_telegram_bot.py")


if __name__ == '__main__':
    main()