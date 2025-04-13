import binaryninja

HEADLESS_MODE = False
try:
    from binaryninjaui import Sidebar
    from .views.sidebar import FunalyzerSidebarWidgetType
    Sidebar.addSidebarWidgetType(FunalyzerSidebarWidgetType())
except binaryninja.UIPluginInHeadlessError:
    # We're in a headless environment, so UI modules are not available
    HEADLESS_MODE = True


