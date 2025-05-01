from binaryninja.log import log_error, log_info, log_debug
from binaryninjaui import (
    SidebarWidget,
    UIActionHandler,
    SidebarWidgetLocation,
    SidebarContextSensitivity,
    SidebarWidgetType,
)
from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QImage, QPainter, QFont, QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QTreeWidget,
    QTreeWidgetItem,
    QTextEdit,
    QSpacerItem,
    QGridLayout,
)
import time
from ..core.database import FunalyzerDatabase
from ..core.parser import LibDescriptor
from ..llm.request import llm_request, LLM_REQUEST_TYPE
from ..libmatch.libmatch import LibMatch


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
        self.selected_function = None

        # ---- Begin UI Items -----
        layout = QVBoxLayout()
        title = QLabel(name, self)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        spacer_small = QSpacerItem(0, 20)
        spacer_medium = QSpacerItem(0, 50)

        # ---- Function tree -----
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Function Name", "Address", "Possible function name"])
        self.tree.setColumnCount(3)
        self.tree.header().resizeSection(0, 150)
        self.tree.header().resizeSection(2, 170)

        self.tree.itemClicked.connect(self.on_item_clicked)
        self.tree.itemDoubleClicked.connect(self.on_item_double_clicked)

        layout.addWidget(self.tree)

        self.btn_ask_llm = QPushButton("Ask LLM")
        self.btn_ask_llm.clicked.connect(self.on_btn_ask_llm_click)
        layout.addWidget(self.btn_ask_llm)

        layout.addItem(spacer_small)

        # ---- LLM Output -----
        title = QLabel("LLM Output", self)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.llm_output = QTextEdit()
        self.llm_output.setReadOnly(True)
        layout.addWidget(self.llm_output)

        layout.addItem(spacer_medium)

        # ---- Options -----
        grid = QGridLayout()

        self.options = [QCheckBox("LibMatch"), QCheckBox("LLM")]
        for row in range(1):  # 3 rows
            for col in range(len(self.options)):  # 3 columns
                grid.addWidget(self.options[row + col], row, col)
        self.options[0].setChecked(True)

        layout.addLayout(grid)

        # ---- Buttons -----
        self.btn_train_model = QPushButton("Generate DB")
        self.btn_train_model.clicked.connect(self.on_btn_train_click)

        self.btn_analyse = QPushButton("Analyze")
        self.btn_analyse.clicked.connect(self.on_btn_analyse_click)

        layout.addWidget(self.btn_train_model)
        layout.addWidget(self.btn_analyse)

        # ---- Set layout ----

        self.setLayout(layout)

    def on_item_clicked(self, item, column):
        address = int(item.text(1), 16)
        if address:
            self.selected_func_addr = address
        else:
            self.selected_func_addr = 0

    def on_item_double_clicked(self, item, column):
        current_scroll_position = self.tree.verticalScrollBar().value()

        selected_item_text = item.text(0)
        address = int(item.text(1), 16)
        self.bv.navigate(self.bv.view, address)

        self.tree.verticalScrollBar().setValue(current_scroll_position)

        items = self.tree.findItems(selected_item_text, Qt.MatchExactly, 0)
        if items:
            self.tree.setCurrentItem(items[0])
            items[0].setSelected(True)

    def on_btn_ask_llm_click(self):
        function = self.bv.get_function_at(self.selected_func_addr)
        resp = llm_request(LLM_REQUEST_TYPE.ANALYZE, function)
        self.llm_output.setPlainText(resp)

    def on_btn_train_click(self):
        log_info("Well, your CPU cores are mine now, because I need them to make a DB :)")
        start = time.perf_counter()
        try:
            db = FunalyzerDatabase.create_from_path("/home/dave/hslu/SEM6/BAA/libmatch/objects/arm-none-eabi")
            db.save_to('/home/dave/arm_none_eabi.fdb', True)
        except Exception as e:
            log_error(f"failed to generate DB: {e}")

        log_debug(f"Generating the DB took {time.perf_counter() - start:.5f}s")

    def on_btn_analyse_click(self):
        """Analyse the current binary view.
        Tries to match unknown functions to known functions.
        """
        if not self.bv:
            log_error("No binary view present")
        elif self.options[0].isChecked(): # LibMatch
            # LibMatch
            fdb = FunalyzerDatabase.load_from_path('/home/dave/arm_none_eabi.fdb')
            if fdb:
                lib_descriptor = LibDescriptor(self.bv)
                lm = LibMatch(lib_descriptor, fdb)
                lm.match(lib_descriptor, fdb)
            else:
                log_error("Failed to load database")
        elif self.options[1].isChecked(): # LMM
            pass
        else:
            log_error("No analyze option selected")
             

    def notifyViewChanged(self, view_frame):
        if view_frame is None:
            self.view_frame = None
            self.view = None
            log_debug("can't update withou bv")
            return
        else:
            self.view = view_frame.getCurrentViewInterface()
            self.view_frame = view_frame
            self.bv = view_frame.getCurrentBinaryView()

        # functions = [func for func in self.bv.functions if func.name.startswith("sub_")]
        functions = [func for func in self.bv.functions]
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

