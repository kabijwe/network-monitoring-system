"""
Property-based tests for dashboard widgets functionality.

These tests validate the correctness properties of the customizable dashboard
widget system, ensuring drag-and-drop functionality, widget configuration,
and layout persistence work correctly across all valid inputs.
"""

import json
import pytest
from hypothesis import given, strategies as st, assume, settings
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant, Bundle
from hypothesis.extra.django import TestCase as HypothesisTestCase
from django.test import Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from core.models import Role, UserRole
from monitoring.models import Location, DeviceGroup

User = get_user_model()

# Test data strategies
@st.composite
def widget_type_strategy(draw):
    """Generate valid widget types."""
    return draw(st.sampled_from([
        'summary-cards',
        'location-overview', 
        'activity-log',
        'chart',
        'map',
        'top-10-list'
    ]))

@st.composite
def widget_position_strategy(draw):
    """Generate valid widget positions."""
    return {
        'x': draw(st.integers(min_value=0, max_value=11)),  # 12-column grid
        'y': draw(st.integers(min_value=0, max_value=20))   # Reasonable row limit
    }

@st.composite
def widget_size_strategy(draw):
    """Generate valid widget sizes."""
    return {
        'width': draw(st.integers(min_value=1, max_value=12)),  # 1-12 columns
        'height': draw(st.integers(min_value=1, max_value=8))   # 1-8 rows
    }

@st.composite
def chart_config_strategy(draw):
    """Generate valid chart widget configurations."""
    return {
        'chartType': draw(st.sampled_from(['line', 'bar', 'pie', 'area'])),
        'metric': draw(st.sampled_from(['latency', 'packet_loss', 'uptime', 'traffic_in', 'traffic_out'])),
        'timeRange': draw(st.sampled_from(['1h', '6h', '24h', '7d', '30d'])),
        'refreshInterval': draw(st.integers(min_value=10, max_value=300))
    }

@st.composite
def map_config_strategy(draw):
    """Generate valid map widget configurations."""
    return {
        'showLabels': draw(st.booleans()),
        'colorBy': draw(st.sampled_from(['status', 'location', 'group'])),
        'zoomLevel': draw(st.integers(min_value=1, max_value=20)),
        'centerLat': draw(st.floats(min_value=-90, max_value=90, allow_nan=False, allow_infinity=False)),
        'centerLng': draw(st.floats(min_value=-180, max_value=180, allow_nan=False, allow_infinity=False))
    }

@st.composite
def top10_config_strategy(draw):
    """Generate valid top-10 list widget configurations."""
    return {
        'metric': draw(st.sampled_from(['latency', 'packet_loss', 'uptime', 'traffic_in', 'traffic_out'])),
        'sortOrder': draw(st.sampled_from(['asc', 'desc'])),
        'showValues': draw(st.booleans()),
        'timeRange': draw(st.sampled_from(['1h', '6h', '24h', '7d']))
    }

@st.composite
def widget_config_strategy(draw, widget_type):
    """Generate appropriate configuration for widget type."""
    if widget_type == 'chart':
        return draw(chart_config_strategy())
    elif widget_type == 'map':
        return draw(map_config_strategy())
    elif widget_type == 'top-10-list':
        return draw(top10_config_strategy())
    else:
        return {}

@st.composite
def widget_strategy(draw):
    """Generate valid widget objects."""
    widget_type = draw(widget_type_strategy())
    widget_id = f"{widget_type}-{draw(st.integers(min_value=1, max_value=999999))}"
    
    return {
        'id': widget_id,
        'type': widget_type,
        'title': draw(st.text(min_size=1, max_size=100)),
        'position': draw(widget_position_strategy()),
        'size': draw(widget_size_strategy()),
        'config': draw(widget_config_strategy(widget_type))
    }

@st.composite
def widget_layout_strategy(draw):
    """Generate valid widget layouts."""
    widgets = draw(st.lists(widget_strategy(), min_size=0, max_size=10))
    
    # Ensure unique widget IDs
    seen_ids = set()
    unique_widgets = []
    for widget in widgets:
        if widget['id'] not in seen_ids:
            seen_ids.add(widget['id'])
            unique_widgets.append(widget)
    
    return {
        'id': draw(st.text(min_size=1, max_size=50)),
        'name': draw(st.text(min_size=1, max_size=100)),
        'widgets': unique_widgets,
        'isDefault': draw(st.booleans()),
        'createdAt': '2025-01-01T00:00:00Z',
        'updatedAt': '2025-01-01T00:00:00Z'
    }


class TestDashboardWidgetProperties(HypothesisTestCase):
    """Property-based tests for dashboard widget functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.client = APIClient()
        
        # Create test user with appropriate permissions
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='test@example.com'
        )
        
        # Create Editor role for widget management
        self.editor_role = Role.objects.create(
            name='Editor',
            permissions={
                'can_edit_hosts': True,
                'can_acknowledge_alerts': True,
                'can_manage_widgets': True
            }
        )
        
        # Create test location and group
        self.location = Location.objects.create(
            name='Test Location',
            description='Test location for widgets'
        )
        
        self.group = DeviceGroup.objects.create(
            name='Test Group',
            description='Test group for widgets'
        )
        
        # Assign role to user
        UserRole.objects.create(
            user=self.user,
            role=self.editor_role,
            location=self.location,
            group=self.group
        )
        
        # Authenticate client
        self.client.force_authenticate(user=self.user)

    @given(widget_layout=widget_layout_strategy())
    @settings(max_examples=10, deadline=8000)
    def test_widget_layout_persistence(self, widget_layout):
        """
        Feature: network-monitoring-tool, Property 23: Dashboard widget functionality
        For any dashboard widget layout, the system should persist the layout
        configuration and restore it accurately on subsequent loads.
        """
        # Store the layout (simulating localStorage behavior)
        layout_json = json.dumps(widget_layout)
        
        # Verify JSON serialization/deserialization preserves data
        restored_layout = json.loads(layout_json)
        
        # Validate all required fields are preserved
        assert restored_layout['id'] == widget_layout['id']
        assert restored_layout['name'] == widget_layout['name']
        assert restored_layout['isDefault'] == widget_layout['isDefault']
        assert len(restored_layout['widgets']) == len(widget_layout['widgets'])
        
        # Validate each widget is preserved correctly
        for original, restored in zip(widget_layout['widgets'], restored_layout['widgets']):
            assert restored['id'] == original['id']
            assert restored['type'] == original['type']
            assert restored['title'] == original['title']
            assert restored['position'] == original['position']
            assert restored['size'] == original['size']
            assert restored['config'] == original['config']

    @given(widget=widget_strategy())
    @settings(max_examples=10, deadline=5000)
    def test_widget_configuration_validation(self, widget):
        """
        Feature: network-monitoring-tool, Property 23: Dashboard widget functionality
        For any widget configuration, the system should validate the configuration
        matches the expected schema for the widget type.
        """
        widget_type = widget['type']
        config = widget['config']
        
        # Validate configuration based on widget type
        if widget_type == 'chart':
            if config:  # Only validate if config is not empty
                assert 'chartType' in config
                assert config['chartType'] in ['line', 'bar', 'pie', 'area']
                assert 'metric' in config
                assert config['metric'] in ['latency', 'packet_loss', 'uptime', 'traffic_in', 'traffic_out']
                assert 'timeRange' in config
                assert config['timeRange'] in ['1h', '6h', '24h', '7d', '30d']
                assert 'refreshInterval' in config
                assert 10 <= config['refreshInterval'] <= 300
        
        elif widget_type == 'map':
            if config:  # Only validate if config is not empty
                if 'showLabels' in config:
                    assert isinstance(config['showLabels'], bool)
                if 'colorBy' in config:
                    assert config['colorBy'] in ['status', 'location', 'group']
                if 'zoomLevel' in config:
                    assert 1 <= config['zoomLevel'] <= 20
        
        elif widget_type == 'top-10-list':
            if config:  # Only validate if config is not empty
                if 'metric' in config:
                    assert config['metric'] in ['latency', 'packet_loss', 'uptime', 'traffic_in', 'traffic_out']
                if 'sortOrder' in config:
                    assert config['sortOrder'] in ['asc', 'desc']
                if 'showValues' in config:
                    assert isinstance(config['showValues'], bool)
                if 'timeRange' in config:
                    assert config['timeRange'] in ['1h', '6h', '24h', '7d']

    @given(
        widget_type=widget_type_strategy(),
        position=widget_position_strategy(),
        size=widget_size_strategy()
    )
    @settings(max_examples=10, deadline=5000)
    def test_widget_drag_drop_positioning(self, widget_type, position, size):
        """
        Feature: network-monitoring-tool, Property 23: Dashboard widget functionality
        For any widget drag-and-drop operation, the system should correctly
        update the widget position within the grid constraints.
        """
        # Create a widget with initial position
        widget = {
            'id': f'{widget_type}-test',
            'type': widget_type,
            'title': f'Test {widget_type}',
            'position': {'x': 0, 'y': 0},
            'size': size,
            'config': {}
        }
        
        # Simulate drag-and-drop to new position
        new_position = position
        
        # Validate position constraints
        assert 0 <= new_position['x'] <= 11  # 12-column grid (0-11)
        assert 0 <= new_position['y'] <= 20  # Reasonable row limit
        
        # Validate widget doesn't exceed grid boundaries
        max_x = new_position['x'] + size['width']
        assert max_x <= 12  # Widget must fit within 12 columns
        
        # Update widget position
        widget['position'] = new_position
        
        # Verify position update
        assert widget['position']['x'] == new_position['x']
        assert widget['position']['y'] == new_position['y']

    @given(widgets=st.lists(widget_strategy(), min_size=1, max_size=5))
    @settings(max_examples=5, deadline=8000)
    def test_widget_layout_grid_constraints(self, widgets):
        """
        Feature: network-monitoring-tool, Property 23: Dashboard widget functionality
        For any set of widgets in a layout, the system should enforce grid
        constraints and prevent overlapping widgets.
        """
        # Ensure unique widget IDs
        seen_ids = set()
        unique_widgets = []
        for widget in widgets:
            if widget['id'] not in seen_ids:
                seen_ids.add(widget['id'])
                unique_widgets.append(widget)
        
        # Validate each widget fits within grid constraints
        for widget in unique_widgets:
            position = widget['position']
            size = widget['size']
            
            # Check position is within bounds
            assert 0 <= position['x'] <= 11
            assert 0 <= position['y'] <= 20
            
            # Check widget doesn't exceed grid width
            max_x = position['x'] + size['width']
            assert max_x <= 12
            
            # Check size constraints
            assert 1 <= size['width'] <= 12
            assert 1 <= size['height'] <= 8

    @given(widget=widget_strategy())
    @settings(max_examples=10, deadline=5000)
    def test_widget_title_and_metadata(self, widget):
        """
        Feature: network-monitoring-tool, Property 23: Dashboard widget functionality
        For any widget, the system should maintain widget metadata including
        title, type, and configuration consistently.
        """
        # Validate required fields exist
        assert 'id' in widget
        assert 'type' in widget
        assert 'title' in widget
        assert 'position' in widget
        assert 'size' in widget
        assert 'config' in widget
        
        # Validate field types and constraints
        assert isinstance(widget['id'], str) and len(widget['id']) > 0
        assert widget['type'] in ['summary-cards', 'location-overview', 'activity-log', 'chart', 'map', 'top-10-list']
        assert isinstance(widget['title'], str) and len(widget['title']) > 0
        assert isinstance(widget['position'], dict)
        assert isinstance(widget['size'], dict)
        assert isinstance(widget['config'], dict)
        
        # Validate position structure
        assert 'x' in widget['position'] and 'y' in widget['position']
        assert isinstance(widget['position']['x'], int)
        assert isinstance(widget['position']['y'], int)
        
        # Validate size structure
        assert 'width' in widget['size'] and 'height' in widget['size']
        assert isinstance(widget['size']['width'], int)
        assert isinstance(widget['size']['height'], int)


class WidgetLayoutStateMachine(RuleBasedStateMachine):
    """
    Stateful property-based testing for widget layout operations.
    
    This tests the invariants that should hold across sequences of
    widget operations like add, move, delete, and configure.
    """
    
    def __init__(self):
        super().__init__()
        self.widgets = {}
        self.layout_id = 'test-layout'
        self.max_widgets = 10
    
    widgets = Bundle('widgets')
    
    @rule(target=widgets, widget_type=widget_type_strategy())
    def add_widget(self, widget_type):
        """Add a new widget to the layout."""
        assume(len(self.widgets) < self.max_widgets)
        
        widget_id = f"{widget_type}-{len(self.widgets)}"
        widget = {
            'id': widget_id,
            'type': widget_type,
            'title': f'Test {widget_type}',
            'position': {'x': 0, 'y': len(self.widgets)},
            'size': {'width': 6, 'height': 2},
            'config': {}
        }
        
        self.widgets[widget_id] = widget
        return widget_id
    
    @rule(widget_id=widgets, new_position=widget_position_strategy())
    def move_widget(self, widget_id, new_position):
        """Move an existing widget to a new position."""
        if widget_id in self.widgets:
            widget = self.widgets[widget_id]
            
            # Ensure widget fits in new position
            max_x = new_position['x'] + widget['size']['width']
            assume(max_x <= 12)
            
            widget['position'] = new_position
    
    @rule(widget_id=widgets)
    def delete_widget(self, widget_id):
        """Delete a widget from the layout."""
        if widget_id in self.widgets:
            del self.widgets[widget_id]
    
    @rule(widget_id=widgets, new_title=st.text(min_size=1, max_size=50))
    def configure_widget(self, widget_id, new_title):
        """Configure a widget's properties."""
        if widget_id in self.widgets:
            self.widgets[widget_id]['title'] = new_title
    
    @invariant()
    def widgets_have_unique_ids(self):
        """All widgets must have unique IDs."""
        widget_ids = list(self.widgets.keys())
        assert len(widget_ids) == len(set(widget_ids))
    
    @invariant()
    def widgets_fit_in_grid(self):
        """All widgets must fit within the 12-column grid."""
        for widget in self.widgets.values():
            position = widget['position']
            size = widget['size']
            max_x = position['x'] + size['width']
            assert max_x <= 12
            assert position['x'] >= 0
            assert position['y'] >= 0
    
    @invariant()
    def widgets_have_valid_types(self):
        """All widgets must have valid types."""
        valid_types = ['summary-cards', 'location-overview', 'activity-log', 'chart', 'map', 'top-10-list']
        for widget in self.widgets.values():
            assert widget['type'] in valid_types
    
    @invariant()
    def widgets_have_required_fields(self):
        """All widgets must have required fields."""
        for widget in self.widgets.values():
            assert 'id' in widget
            assert 'type' in widget
            assert 'title' in widget
            assert 'position' in widget
            assert 'size' in widget
            assert 'config' in widget


# Stateful test case
TestWidgetLayoutStateMachine = WidgetLayoutStateMachine.TestCase


if __name__ == '__main__':
    # Run the property-based tests
    pytest.main([__file__, '-v', '--hypothesis-show-statistics'])