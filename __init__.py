from binaryninjaui import Sidebar
from funalyzer.views.sidebar import FunalyzerSidebarWidgetType

# Register the sidebar widget
Sidebar.addSidebarWidgetType(FunalyzerSidebarWidgetType())
