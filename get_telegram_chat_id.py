#!/usr/bin/env python3
"""
Simple script to get your Telegram chat ID after starting conversation with bot.
"""

import requests
import json

def get_chat_id():
    bot_token = "8286757654:AAFUkBe9gJ6ZS4ovwg5Q1xt2whKAR1uGDcc"
    
    print("🤖 Getting your Telegram Chat ID...")
    print("=" * 50)
    
    try:
        # Get updates from Telegram
        url = f"https://api.telegram.org/bot{bot_token}/getUpdates"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if not data.get('ok'):
            print(f"❌ Error from Telegram API: {data.get('description', 'Unknown error')}")
            return
        
        updates = data.get('result', [])
        
        if not updates:
            print("❌ No messages found!")
            print("\nPlease:")
            print("1. Go to https://t.me/kabijwe_bot")
            print("2. Click 'START' or send any message")
            print("3. Run this script again")
            return
        
        print(f"✅ Found {len(updates)} recent messages:")
        print("-" * 50)
        
        for update in updates[-5:]:  # Show last 5 messages
            message = update.get('message', {})
            chat = message.get('chat', {})
            from_user = message.get('from', {})
            
            chat_id = chat.get('id')
            username = from_user.get('username', 'N/A')
            first_name = from_user.get('first_name', 'N/A')
            phone = from_user.get('phone_number', 'N/A')
            text = message.get('text', 'N/A')
            
            print(f"Chat ID: {chat_id}")
            print(f"Username: @{username}")
            print(f"Name: {first_name}")
            print(f"Message: {text}")
            print("-" * 30)
        
        # Get the most recent chat ID
        if updates:
            latest_chat_id = updates[-1]['message']['chat']['id']
            print(f"🎯 Your Chat ID: {latest_chat_id}")
            
            # Test sending a message
            print(f"\n🧪 Testing notification to Chat ID: {latest_chat_id}")
            test_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            test_payload = {
                'chat_id': latest_chat_id,
                'text': '🎉 Success! Your Network Monitoring System can now send Telegram notifications!\n\nThis is a test message from your NMS bot.',
                'parse_mode': 'Markdown'
            }
            
            test_response = requests.post(test_url, json=test_payload, timeout=10)
            
            if test_response.status_code == 200:
                print("✅ Test message sent successfully!")
                print(f"✅ Your Chat ID is: {latest_chat_id}")
                
                # Update .env file
                try:
                    with open('.env', 'r') as f:
                        env_content = f.read()
                    
                    # Add chat ID info as comment
                    if f"# Telegram Chat ID: {latest_chat_id}" not in env_content:
                        env_content += f"\n# Telegram Chat ID: {latest_chat_id}\n"
                        
                        with open('.env', 'w') as f:
                            f.write(env_content)
                        
                        print("✅ Added chat ID to .env file as reference")
                except Exception as e:
                    print(f"⚠️  Could not update .env file: {e}")
                
                return latest_chat_id
            else:
                print(f"❌ Test message failed: {test_response.text}")
                
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == '__main__':
    get_chat_id()