import binaryninja

HEADLESS_MODE = False
try:
    from binaryninjaui import Sidebar
    from .views.sidebar import FunalyzerSidebarWidgetType
    Sidebar.addSidebarWidgetType(FunalyzerSidebarWidgetType())
except binaryninja.UIPluginInHeadlessError:
    # necessary for automated tests
    HEADLESS_MODE = True


import binaryninja as bn
import multiprocessing as mp
import threading
from binaryninja.log import log_info




def analyze_binary(q):
    import time
    with open('/tmp/yups.txt', 'w') as f:
        f.write('yups')
    q.put("Child process started")
    for i in range(1, 6):
        q.put(f"Processing item {i}/5")
        time.sleep(1)
    q.put("Finalizing results")

def log_handler(q):
    while True:
        msg = q.get()
        if msg is None:
            break
        bn.execute_on_main_thread(lambda msg=msg: log_info(str(msg)))

def analyze():
    ctx = mp.get_context("spawn")
    log_queue = ctx.Queue()
    handler_thread = threading.Thread(target=log_handler, args=(log_queue,), daemon=True)
    handler_thread.start()
    process = ctx.Process(target=analyze_binary, args=(log_queue,))
    process.start()
    def monitor():
        process.join()
        log_queue.put(None)
        handler_thread.join()
        bn.execute_on_main_thread(lambda: log_info("Task completed"))
    t = threading.Thread(target=monitor, daemon=True)
    t.start()
    t.join()
