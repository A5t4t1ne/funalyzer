import binaryninja
try:
    from binaryninjaui import Sidebar
    from .views.sidebar import FunalyzerSidebarWidgetType
    
    # Register the sidebar widget
    Sidebar.addSidebarWidgetType(FunalyzerSidebarWidgetType())
except binaryninja.UIPluginInHeadlessError:
    # We're in a headless environment, so UI modules are not available
    pass
