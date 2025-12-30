"""
URL configuration for frontend React app.
"""
from django.urls import path
from django.views.generic import TemplateView

app_name = 'frontend'

urlpatterns = [
    # Serve React app for all frontend routes
    path('', TemplateView.as_view(template_name='index.html'), name='index'),
    
    # React Router will handle client-side routing
    # All other paths should also serve the React app
    path('<path:path>', TemplateView.as_view(template_name='index.html'), name='react_routes'),
]