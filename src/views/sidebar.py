from binaryninja import log_error, log_info, log_debug
from binaryninja.binaryview import BinaryView
from binaryninjaui import (
    Sidebar,
    SidebarWidget,
    UIActionHandler,
    SidebarWidgetLocation,
    SidebarContextSensitivity,
    SidebarWidgetType,
    UIContext,
)
from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QImage, QPainter, QFont, QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QTreeWidget,
    QTreeWidgetItem
)
from ..core.database import FunalyzerDatabase
import time
from google import genai


PROMPT = "Along with this message I send you low level intermediary instructions from disassembled code. The code was disassembled with binary ninja. Can you try to guess what the code does?\n\n"


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

        self.options = [QCheckBox("LibMatch"), QCheckBox("LLM")]

        self.btn_train_model = QPushButton("Train")
        self.btn_train_model.clicked.connect(self.on_btn_train_click)

        self.btn_analyse = QPushButton("Analyze")
        self.btn_analyse.clicked.connect(self.on_btn_analyse_click)

        for option in self.options:
            layout.addWidget(option)

        layout.addWidget(self.btn_train_model)
        layout.addWidget(self.btn_analyse)


        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Function Name", "Address", "Possible function name"])
        self.tree.setColumnCount(3)
        self.tree.header().resizeSection(0, 150)
        self.tree.header().resizeSection(2, 170)

        self.tree.itemClicked.connect(self.on_item_clicked)

        layout.addWidget(self.tree)


        self.llm_output = QTextEdit()
        self.llm_output.setReadOnly(True)
        layout.addWidget(self.llm_output)


        layout.addStretch()

        self.setLayout(layout)

    def on_item_clicked(self, item, column):
        address = item.data(0, Qt.UserRole)
        if address:
            # print(f"Jumping to address: {hex(address)} {item}, {column}")
            pass

    def on_btn_train_click(self):
        log_info("Well, your CPU cores are mine now, because I need them to make a DB :)")
        time.sleep(0.5)
        start = time.perf_counter()
        try:
            db = FunalyzerDatabase.create_from_path("/home/dave/hslu/SEM6/BAA/libmatch/objects/arm-none-eabi")
            db.save_to("arm_none_eabi.fdb", True)
        except Exception as e:
            log_error(f"failed to generate DB: {e}")
        log_debug(f"Generating the DB took {time.perf_counter() - start:.5f}s")

    def on_btn_analyse_click(self):
        """Analyse the current binary view.
        Tries to match unknown functions to known functions.
        """
        log_info("Analysing...")
        il_funcs = []
        func_names = ""
        if self.view_frame:
            bv = self.view_frame.getCurrentBinaryView()
            if isinstance(bv, BinaryView):
                log_info("Unknown functions found:")
                for func in list(bv.functions):
                    if func.name == "sub_4700":
                        func_il = func.low_level_il
                        il_funcs.append("\n".join([str(instr) for instr in func_il.instructions]))

                        log_info(f"> {func.name}")
                        func_names += f"\n{func.name}"
                if len(il_funcs) > 0:
                    # self.txt_funcs.setPlainText(func_names)
                    self.txt_funcs.setPlainText(str(il_funcs[0]))
                    log_info("Starting LLM API request")
                    API_KEY = "AIzaSyBO4nlCdN0yDklPhLpa2V8Y5nns5KX7gDI"
                    client = genai.Client(api_key=API_KEY)
                    response = client.models.generate_content(model="gemini-2.0-flash", contents=[PROMPT + il_funcs[0]])
                    log_info(response.text)
                    with open("response.txt", "w") as f:
                        f.write(response.text)
                else:
                    self.txt_funcs.setPlainText("None found")
        else:
            log_error("No view frame, did you open a binary file?")

    def notifyViewChanged(self, view_frame):
        if view_frame is None:
            self.view_frame = None
            self.view = None
        else:
            self.view = view_frame.getCurrentViewInterface()
            self.view_frame = view_frame
            self.bv = view_frame.getCurrentBinaryView()

        functions = [func for func in self.bv.functions if func.name.startswith("sub_")]
        self.tree.clear()
        for func in functions:
            item = QTreeWidgetItem([func.name, hex(func.start), ""])
            # item.setData(1, Qt.UserRole, "a") # set name of function
            self.tree.addTopLevelItem(item)

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


def update_unknown_functions(bv: BinaryView):
    log_info("yep, definitely came here")
    ctx = UIContext.activeContext()
    if not ctx:
        return

    # Access the main window and sidebar widgets
    main_window = ctx.mainWindow()
    sidebar = main_window.findChild(Sidebar)
    log_info(dir(sidebar))

    # Get all instances of the registered widget type
    for widget in SidebarWidgetType.instances:
        if isinstance(widget, FunalyzerSidebarWidget):
            functions = [func for func in bv.functions if func.name.startswith("sub_")]
            funcs_str = "\n".join([str(f.name) for f in functions])
            widget.update_functions(funcs_str)

    # Find our sidebar widget in the current window
    # sidebar = ctx.getSidebar()
    # if not sidebar:
    #     return

    # # Locate an instance of our custom widget
    # widget = next((w for w in sidebar.widgets if isinstance(w, FunalyzerSidebarWidget)), None)

    # if widget:
    #     functions = [func for func in bv.functions if func.name.startswith('sub_')]
    #     funcs_str = "\n".join([str(f.name) for f in functions])
    #     widget.update_functions(funcs_str)


# BinaryViewType.add_binaryview_finalized_event(update_unknown_functions)
