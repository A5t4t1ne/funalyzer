from binaryninja import log_error, log_info, log_debug
from binaryninja.binaryview import BinaryView
from binaryninjaui import (
    SidebarWidget,
    UIActionHandler,
    SidebarWidgetLocation,
    SidebarContextSensitivity,
    SidebarWidgetType,
)
from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QImage, QPainter, QFont, QColor
from PySide6.QtWidgets import QCheckBox, QLabel, QPushButton, QVBoxLayout
from ..core.database import FunalyzerDatabase
from ..core.parser import UniformedFunction
import time


# Sidebar widgets must derive from SidebarWidget, not QWidget. SidebarWidget is
# a QWidget but provides callbacks for sidebar events, and must be created with
# a title.
class FunalyzerSidebarWidget(SidebarWidget):
    """The sidebar widget for Funalyzer.

    Args:
        SidebarWidget: Base class for all sidebar widgets.
    """

    def __init__(self, name, frame, data):
        super().__init__(name)
        self.data = data
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)
        self.view_frame = frame
        self.view = None

        layout = QVBoxLayout()
        title = QLabel(name, self)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.options = [QCheckBox("LibMatch"), QCheckBox("LLM"), QCheckBox("Other")]

        self.btn_train_model = QPushButton("Train")
        self.btn_train_model.clicked.connect(self.on_btn_train_click)

        self.btn_analyse = QPushButton("Analyze")
        self.btn_analyse.clicked.connect(self.on_btn_analyse_click)

        for option in self.options:
            layout.addWidget(option)

        layout.addWidget(self.btn_train_model)
        layout.addWidget(self.btn_analyse)
        layout.addStretch()

        self.setLayout(layout)

    def on_btn_train_click(self):
        log_info("Well, your CPU cores are mine now, because I need them to make a DB :)")
        if self.view_frame:
            bv = self.view_frame.getCurrentBinaryView()

            start = time.perf_counter()
            log_debug(f"found {len(bv.functions)} functions")
            try:
                db = FunalyzerDatabase.create_from_path("/home/dave/hslu/SEM6/BAA/libmatch/objects/arm-none-eabi")
                db.save_to("arm_none_eabi.fdb", True)
            except Exception as e:
                log_error(f"failed to generate DB: {e}")
            log_debug(f"Generating the DB took {time.perf_counter() - start:.5f}s")
        else:
            log_error("No view frame, did you open a binary file?")

    def on_btn_analyse_click(self):
        """Analyse the current binary view.
        Tries to match unknown functions to known functions.
        """
        log_info("Analysing...")
        if self.view_frame:
            bv = self.view_frame.getCurrentBinaryView()
            if isinstance(bv, BinaryView):
                log_info("unknown functions found:")
                for func in list(bv.functions)[:10]:
                    if func.name.startswith("sub_"):
                        log_info(f"Function: {func.name}")
        else:
            log_error("No view frame, did you open a binary file?")

    def notifyViewChanged(self, view_frame):
        if view_frame is None:
            self.view_frame = None
            self.view = None
        else:
            self.view = view_frame.getCurrentViewInterface()
            self.view_frame = view_frame

    def contextMenuEvent(self, _):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)


class FunalyzerSidebarWidgetType(SidebarWidgetType):
    def __init__(self):
        # Sidebar icons are 28x28 points. Should be at least 56x56 pixels for
        # HiDPI display compatibility. They will be automatically made theme
        # aware, so you need only provide a grayscale image, where white is
        # the color of the shape.
        icon = QImage(56, 56, QImage.Format_RGB32)
        icon.fill(0)

        # Render an "F" as the example icon
        p = QPainter()
        p.begin(icon)
        p.setFont(QFont("Open Sans", 56))
        p.setPen(QColor(255, 255, 255, 255))
        p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "F")
        p.end()

        SidebarWidgetType.__init__(self, icon, "Funalyzer")

    def createWidget(self, frame, data):
        # This callback is called when a widget needs to be created for a given context. Different
        # widgets are created for each unique BinaryView. They are created on demand when the sidebar
        # widget is visible and the BinaryView becomes active.
        return FunalyzerSidebarWidget("Funalyzer", frame, data)

    def defaultLocation(self):
        # Default location in the sidebar where this widget will appear
        return SidebarWidgetLocation.LeftContent

    def contextSensitivity(self):
        # Context sensitivity controls which contexts have separate instances of the sidebar widget.
        # Using `contextSensitivity` instead of the deprecated `viewSensitive` callback allows sidebar
        # widget implementations to reduce resource usage.

        # This example widget uses a single instance and detects view changes.
        return SidebarContextSensitivity.SelfManagedSidebarContext
