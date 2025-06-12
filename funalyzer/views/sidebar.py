from pathlib import Path
from binaryninja.log import log_error, log_info, log_debug, log_warn
from binaryninja.function import Function
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
    QLineEdit,
    QFileDialog
)
import time
from funalyzer.core.database import FunalyzerDatabase
from funalyzer.core.parser import LibDescriptor
from funalyzer.llm.llm import llm_request, LLM_REQUEST_TYPE
from funalyzer.libmatch.libmatch import LibMatch
import asyncio


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

        # layout.addLayout(grid)

        # ---- Path ----

        self.path_field = QLineEdit(self)
        self.path_field.setReadOnly(True)
        self.path_button = QPushButton("Select Lib-Path", self)
        self.path_button.clicked.connect(self.select_path)
        layout.addWidget(self.path_field)
        layout.addWidget(self.path_button)

        # ---- Buttons -----
        self.btn_train_model = QPushButton("Generate DB")
        self.btn_train_model.clicked.connect(self.on_btn_generate_db_click)

        self.btn_analyse = QPushButton("Analyze")
        self.btn_analyse.clicked.connect(self.on_btn_analyse_click)

        layout.addWidget(self.btn_train_model)
        layout.addWidget(self.btn_analyse)

        # ---- Set layout ----

        self.setLayout(layout)

    def select_path(self):
        path = QFileDialog.getExistingDirectory(self, "Select File")
        if path:
            self.path_field.setText(path)

    def on_item_clicked(self, item, _):
        address = int(item.text(1), 16)
        if address:
            self.selected_func_addr = address
        else:
            self.selected_func_addr = 0

    def on_item_double_clicked(self, item, _):
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

        function: Function = self.bv.get_function_at(self.selected_func_addr)
        if isinstance(function, Function):
            resp = asyncio.run(llm_request(self.bv, function, LLM_REQUEST_TYPE.ANALYZE_FUNC))
        else:
            resp = f"Function at {self.selected_func_addr} not found"
        self.llm_output.setPlainText(resp)

    def on_btn_generate_db_click(self) -> None:
        """Generate the database for LibMatch.
        This will parse the given path and create a FunalyzerDatabase and save it to a file.
        """
        start = time.perf_counter()
        try:
            db = FunalyzerDatabase.create_from_path(self.path_field.text())
            db_path = Path(self.path_field.text())
            db_path = db_path.with_suffix('.fdb')
            db.save_to(str(db_path), True)
        except Exception as e:
            log_error(f"failed to generate DB: {e}")

        log_debug(f"Generating the DB took {time.perf_counter() - start:.5f}s")

    def on_btn_analyse_click(self) -> None:
        """Analyse the current binary view using LibMatch and LLM.
        This will use the selected options to either run LibMatch or LLM analysis in order to match functions.
        """
        if not self.bv:
            log_error("No binary view present")
            return
        if self.options[0].isChecked(): # LibMatch
            log_debug("Starting LibMatch analysis")
            start = time.perf_counter()

            p = Path(self.path_field.text())
            p = p.with_suffix('.fdb')
            fdb = FunalyzerDatabase.load_from_path(p)
            if fdb:
                # create descriptor of target file and try to match with database
                binary_descriptor = LibDescriptor(self.bv) 
                lm = LibMatch(binary_descriptor, fdb)
                lm.compute()
                log_debug(f"LibMatch computation took {time.perf_counter() - start:.5f}s")
                matches = lm.match()
                if matches:
                    for addr, name in matches.items():
                        log_info(f"{addr:x} => {name}")
                else:
                    log_warn("No matches found")
            else:
                log_error("Failed to load database")
            log_debug(f"LibMatch matching took {time.perf_counter() - start:.5f}s")
        if self.options[1].isChecked(): # LLM
            pass
             

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

