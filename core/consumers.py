"""
WebSocket consumers for real-time updates.
"""

import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser


class NotificationConsumer(AsyncWebsocketConsumer):
    """Consumer for real-time notifications."""
    
    async def connect(self):
        """Accept WebSocket connection."""
        self.user = self.scope["user"]
        
        if isinstance(self.user, AnonymousUser):
            await self.close()
            return
            
        self.group_name = f"notifications_{self.user.id}"
        
        # Join notification group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        
        await self.accept()

    async def disconnect(self, close_code):
        """Leave notification group."""
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )

    async def notification_message(self, event):
        """Send notification to WebSocket."""
        await self.send(text_data=json.dumps({
            'type': 'notification',
            'message': event['message']
        }))


class StatusConsumer(AsyncWebsocketConsumer):
    """Consumer for real-time status updates."""
    
    async def connect(self):
        """Accept WebSocket connection."""
        self.user = self.scope["user"]
        
        if isinstance(self.user, AnonymousUser):
            await self.close()
            return
            
        # Join status updates group
        await self.channel_layer.group_add(
            "status_updates",
            self.channel_name
        )
        
        await self.accept()

    async def disconnect(self, close_code):
        """Leave status updates group."""
        await self.channel_layer.group_discard(
            "status_updates",
            self.channel_name
        )

    async def status_update(self, event):
        """Send status update to WebSocket."""
        await self.send(text_data=json.dumps({
            'type': 'status_update',
            'data': event['data']
        }))