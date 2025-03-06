from binaryninja import log_error, log_info
from binaryninja.binaryview import BinaryView
from binaryninja.flowgraph import CoreFlowGraph
from binaryninjaui import SidebarWidget, UIActionHandler, SidebarWidgetLocation, SidebarContextSensitivity, SidebarWidgetType
from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QImage, QPainter, QFont, QColor
from PySide6.QtWidgets import QCheckBox, QLabel, QPushButton, QVBoxLayout
import subprocess


# Sidebar widgets must derive from SidebarWidget, not QWidget. SidebarWidget is
# a QWidget but provides callbacks for sidebar events, and must be created with
# a title.
class FunalyzerSidebarWidget(SidebarWidget):
    def __init__(self, name, frame, data):
        super().__init__(name)
        self.data = data
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)
        self.view_frame = None
        self.view = None

        layout = QVBoxLayout()
        title = QLabel(name, self)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.options = [QCheckBox("LibMatch"), QCheckBox("LLM"), QCheckBox("Oth")]
        self.execute_button = QPushButton("Analyze")
        self.execute_button.clicked.connect(self.on_button_click)

        for option in self.options:
            layout.addWidget(option)

        layout.addWidget(self.execute_button)
        layout.addStretch()

        self.setLayout(layout)

    def on_button_click(self):
        log_info("Button clicked")
        # view_frame = UIContext.activeContext().getCurrentViewFrame()
        if self.view_frame:
            bv = self.view_frame.getCurrentBinaryView()
            if isinstance(bv, BinaryView):
                a = "./utils/unblob -U --scoring -L \
                        ./objects/arm-none-eabi.lmdb \
                        -Y ./bins/Nucleo_i2c_master.elf \
                        ./bins/Nucleo_i2c_master_addrs.yml`"

                try:
                    # Run unblob command
                    cmd = [*a.split()]
                    process = subprocess.run(
                        cmd,
                        capture_output=True,  # Capture stdout and stderr
                        text=True,            # Return strings instead of bytes
                        check=True            # Raise exception on error
                    )

                    log_info(f"Command output:\n{process.stdout}")
                except subprocess.CalledProcessError as e:
                    log_error(f"Command failed with error: {e.stderr}")
                except Exception as e:
                    log_error(f"Error running command: {str(e)}")
                else:
                    log_error("No binary view, was the binary file analyzed?")

                for func in bv.functions:
                    log_info(f"Function: {func.name}")

                    # Generate CFG for the function
                    cfg = func.create_graph()

                    # Export CFG as a dot file or visualize it
                    dot_file_path = f"{func.name}_cfg.dot"
                    with open(dot_file_path, "w") as dot_file:
                        dot_file.write(cfg.serialize_to_dot())

                    log_info(f"CFG for {func.name} exported to {dot_file_path}")

        else:
            log_error("No view frame, did you open a binary file?")

    def notifyViewChanged(self, view_frame):
        if view_frame is None:
            self.view_frame = None
            self.view = None
        else:
            self.view = view_frame.getCurrentViewInterface()
            self.view_frame = view_frame

    def contextMenuEvent(self, _event):
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
