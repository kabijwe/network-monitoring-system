#!/usr/bin/env python3
"""
Script to help set up Telegram bot for notifications.

This script will guide you through:
1. Creating a Telegram bot
2. Getting the bot token
3. Finding your chat ID
4. Testing the notification system
"""

import os
import sys
import django
import requests
import json

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nms.settings')
django.setup()

from django.conf import settings
from monitoring.notification_service import test_notification_channel


def print_header(title):
    """Print a formatted header."""
    print("\n" + "="*60)
    print(f" {title}")
    print("="*60)


def print_step(step_num, title):
    """Print a formatted step."""
    print(f"\n{step_num}. {title}")
    print("-" * 40)


def create_telegram_bot_instructions():
    """Show instructions for creating a Telegram bot."""
    print_header("TELEGRAM BOT SETUP INSTRUCTIONS")
    
    print_step(1, "Create a Telegram Bot")
    print("1. Open Telegram and search for @BotFather")
    print("2. Start a chat with BotFather")
    print("3. Send the command: /newbot")
    print("4. Follow the instructions to name your bot")
    print("5. BotFather will give you a bot token that looks like:")
    print("   123456789:ABCdefGHIjklMNOpqrsTUVwxyz")
    
    print_step(2, "Get Your Chat ID")
    print("1. Start a chat with your new bot")
    print("2. Send any message to your bot")
    print("3. We'll help you find your chat ID in the next step")
    
    return input("\nDo you have your bot token? (y/n): ").lower().strip() == 'y'


def get_bot_token():
    """Get bot token from user."""
    print_step(3, "Enter Bot Token")
    while True:
        token = input("Enter your bot token: ").strip()
        if token and ':' in token:
            return token
        print("Invalid token format. Please try again.")


def find_chat_id(bot_token, phone_number):
    """Help user find their chat ID."""
    print_step(4, "Find Your Chat ID")
    print(f"Looking for chat ID for phone number: {phone_number}")
    
    try:
        # Get updates from Telegram
        url = f"https://api.telegram.org/bot{bot_token}/getUpdates"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if not data.get('ok'):
            print(f"Error from Telegram API: {data.get('description', 'Unknown error')}")
            return None
        
        updates = data.get('result', [])
        
        if not updates:
            print("No messages found. Please:")
            print("1. Send a message to your bot in Telegram")
            print("2. Run this script again")
            return None
        
        print(f"Found {len(updates)} recent messages:")
        
        for update in updates[-5:]:  # Show last 5 messages
            message = update.get('message', {})
            chat = message.get('chat', {})
            from_user = message.get('from', {})
            
            chat_id = chat.get('id')
            username = from_user.get('username', 'N/A')
            first_name = from_user.get('first_name', 'N/A')
            phone = from_user.get('phone_number', 'N/A')
            text = message.get('text', 'N/A')
            
            print(f"\nChat ID: {chat_id}")
            print(f"Username: @{username}")
            print(f"Name: {first_name}")
            print(f"Phone: {phone}")
            print(f"Message: {text}")
            print("-" * 30)
        
        # Try to find the most recent chat ID
        if updates:
            latest_chat_id = updates[-1]['message']['chat']['id']
            return str(latest_chat_id)
        
    except Exception as e:
        print(f"Error getting chat ID: {e}")
        return None


def test_telegram_notification(bot_token, chat_id):
    """Test sending a Telegram notification."""
    print_step(5, "Test Telegram Notification")
    
    # Update environment variable for testing
    os.environ['TELEGRAM_BOT_TOKEN'] = bot_token
    os.environ['TELEGRAM_NOTIFICATIONS_ENABLED'] = 'True'
    
    # Reload Django settings
    from importlib import reload
    from django.conf import settings
    reload(settings)
    
    print(f"Testing notification to chat ID: {chat_id}")
    
    try:
        success = test_notification_channel('telegram', chat_id)
        
        if success:
            print("✅ Telegram notification sent successfully!")
            print("Check your Telegram app for the test message.")
            return True
        else:
            print("❌ Failed to send Telegram notification.")
            return False
            
    except Exception as e:
        print(f"❌ Error testing Telegram: {e}")
        return False


def update_env_file(bot_token):
    """Update .env file with Telegram configuration."""
    print_step(6, "Update Configuration")
    
    env_file = '.env'
    env_example_file = '.env.example'
    
    # Read existing .env or create from .env.example
    env_content = []
    
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            env_content = f.readlines()
    elif os.path.exists(env_example_file):
        with open(env_example_file, 'r') as f:
            env_content = f.readlines()
    
    # Update or add Telegram settings
    telegram_settings = {
        'TELEGRAM_NOTIFICATIONS_ENABLED': 'True',
        'TELEGRAM_BOT_TOKEN': bot_token,
    }
    
    # Update existing lines or add new ones
    updated_content = []
    settings_added = set()
    
    for line in env_content:
        line = line.strip()
        if '=' in line:
            key = line.split('=')[0].strip()
            if key in telegram_settings:
                updated_content.append(f"{key}={telegram_settings[key]}\n")
                settings_added.add(key)
            else:
                updated_content.append(line + '\n')
        else:
            updated_content.append(line + '\n')
    
    # Add any missing settings
    for key, value in telegram_settings.items():
        if key not in settings_added:
            updated_content.append(f"{key}={value}\n")
    
    # Write updated .env file
    with open(env_file, 'w') as f:
        f.writelines(updated_content)
    
    print(f"✅ Updated {env_file} with Telegram configuration")
    print("\nTelegram settings added:")
    for key, value in telegram_settings.items():
        print(f"  {key}={value}")


def main():
    """Main function to set up Telegram bot."""
    print_header("NETWORK MONITORING SYSTEM - TELEGRAM SETUP")
    print("This script will help you set up Telegram notifications.")
    
    phone_number = "9842478259"
    
    # Step 1: Instructions
    if not create_telegram_bot_instructions():
        print("\nPlease create a Telegram bot first and run this script again.")
        return
    
    # Step 2: Get bot token
    bot_token = get_bot_token()
    
    # Step 3: Find chat ID
    chat_id = find_chat_id(bot_token, phone_number)
    
    if not chat_id:
        print("\n❌ Could not find chat ID. Please:")
        print("1. Make sure you sent a message to your bot")
        print("2. Run this script again")
        return
    
    print(f"\n✅ Found chat ID: {chat_id}")
    
    # Step 4: Test notification
    if test_telegram_notification(bot_token, chat_id):
        # Step 5: Update configuration
        update_env_file(bot_token)
        
        print_header("SETUP COMPLETE!")
        print("✅ Telegram bot is configured and working!")
        print(f"✅ Bot token: {bot_token[:20]}...")
        print(f"✅ Chat ID: {chat_id}")
        print(f"✅ Phone number: {phone_number}")
        
        print("\nNext steps:")
        print("1. Restart your Django application to load new settings")
        print("2. Test the notification system with: python manage.py test_notifications --channel telegram --recipient", chat_id)
        print("3. Create test alerts to verify the complete notification workflow")
        
    else:
        print("\n❌ Setup failed. Please check your bot token and try again.")


if __name__ == '__main__':
    main()