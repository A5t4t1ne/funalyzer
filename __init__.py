from binaryninjaui import Sidebar
from .sidebar_widget import FunalyzerSidebarWidgetType


# Register the sidebar widget
Sidebar.addSidebarWidgetType(FunalyzerSidebarWidgetType())
