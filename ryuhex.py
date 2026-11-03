
import sys
import os
import tempfile
from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QHBoxLayout, QVBoxLayout, QPushButton,
    QLabel, QFileDialog, QPlainTextEdit,
    QLineEdit, QProgressBar, QMessageBox
)

from rizin_backend import RizinBackend


PAGE_BYTES = 4096


class ExportWorker(QThread):
    progress = Signal(int)
    completed = Signal(str)
    failed = Signal(str)

    def __init__(self, filename, base, output):
        super().__init__()
        self.filename = Path(filename)
        self.base = base
        self.output = Path(output)

    def run(self):
        backend = RizinBackend()
        temp_path = None

        try:
            backend.open_file(self.filename, self.base)

            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.output.parent,
                prefix=".ryusect-",
                suffix=".part",
                delete=False,
            ) as output:
                temp_path = Path(output.name)

                size = backend.file_size
                offset = 0

                output.write(
                    "RYUJINWARE RYUSECT\n"
                    "COMPLETE RAW MIPS32 DISASSEMBLY\n"
                    f"Source: {self.filename}\n"
                    f"File size: {size} bytes\n"
                    f"Mapped base: 0x{self.base:08X}\n"
                    "Endian: little\n"
                    "Note: raw decoding includes data and padding.\n"
                    "=" * 64 + "\n"
                )

                while offset < size:
                    if self.isInterruptionRequested():
                        raise InterruptedError(
                            "Export cancelled"
                        )

                    length = min(
                        PAGE_BYTES, size - offset
                    )

                    address = self.base + offset

                    text = backend.get_disassembly(
                        address=address,
                        byte_count=length,
                    )

                    if not text or not text.strip():
                        raise RuntimeError(
                            "Rizin returned no disassembly "
                            f"at 0x{address:08X}"
                        )

                    output.write(
                        f"\nFILE OFFSET: 0x{offset:08X}\n"
                        f"ADDRESS: 0x{address:08X}\n"
                    )
                    output.write(text)

                    if not text.endswith("\n"):
                        output.write("\n")

                    offset += length

                    if (
                        offset == size
                        or offset % (PAGE_BYTES * 16) == 0
                    ):
                        self.progress.emit(
                            int(offset * 100 / size)
                        )

            os.replace(temp_path, self.output)
            temp_path = None
            self.completed.emit(str(self.output))

        except Exception as error:
            self.failed.emit(str(error))

        finally:
            backend.close()

            if temp_path is not None:
                temp_path.unlink(missing_ok=True)


class RyuHEX(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle(
            "RyujinWARE | RyuSECT v0.2"
        )
        self.resize(1250, 780)

        self.backend = RizinBackend()
        self.current_file = None
        self.current_offset = 0
        self.worker = None

        controls = QVBoxLayout()

        controls.addWidget(
            QLabel("RYUSECT | BINARY INVESTIGATOR")
        )

        self.open_button = QPushButton("Open Binary")
        self.inspect_button = QPushButton(
            "Inspect First 64 Bytes"
        )
        self.disasm_button = QPushButton(
            "View MIPS32 Disassembly"
        )

        controls.addWidget(self.open_button)
        controls.addWidget(self.inspect_button)
        controls.addWidget(self.disasm_button)

        controls.addWidget(
            QLabel("Raw firmware base address")
        )

        self.base_input = QLineEdit("0x0")
        controls.addWidget(self.base_input)

        controls.addWidget(
            QLabel("Jump to file offset")
        )

        self.offset_input = QLineEdit("0x0")
        self.jump_button = QPushButton("Jump")

        controls.addWidget(self.offset_input)
        controls.addWidget(self.jump_button)

        self.first_code_button = QPushButton(
            "Find First Nonzero Region"
        )
        controls.addWidget(self.first_code_button)

        navigation = QHBoxLayout()

        self.prev_button = QPushButton("Previous")
        self.next_button = QPushButton("Next")

        navigation.addWidget(self.prev_button)
        navigation.addWidget(self.next_button)

        controls.addLayout(navigation)

        controls.addWidget(
            QLabel("Complete firmware disassembly")
        )

        self.export_button = QPushButton(
            "Export Whole Disassembly"
        )
        controls.addWidget(self.export_button)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        controls.addWidget(self.progress)

        self.info_label = QLabel(
            "No firmware loaded"
        )
        self.info_label.setWordWrap(True)
        controls.addWidget(self.info_label)

        controls.addStretch()

        self.results = QPlainTextEdit()
        self.results.setReadOnly(True)
        self.results.setFont(
            QFont("Monospace", 10)
        )

        self.results.setPlainText(
            "RyuSECT v0.2 initialized.\n\n"
            "Open a firmware image to begin.\n\n"
            "Disassembly is loaded in 4096-byte windows.\n"
            "Full-file export is also available."
        )

        left = QWidget()
        left.setLayout(controls)
        left.setFixedWidth(290)

        layout = QHBoxLayout()
        layout.addWidget(left)
        layout.addWidget(self.results, 1)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.open_button.clicked.connect(self.open_file)
        self.inspect_button.clicked.connect(
            self.inspect_file
        )
        self.disasm_button.clicked.connect(
            self.start_disassembly
        )
        self.jump_button.clicked.connect(
            self.jump_to_offset
        )
        self.first_code_button.clicked.connect(
            self.find_first_nonzero
        )
        self.prev_button.clicked.connect(
            lambda: self.change_page(-1)
        )
        self.next_button.clicked.connect(
            lambda: self.change_page(1)
        )
        self.export_button.clicked.connect(
            self.export_disassembly
        )

        self.set_navigation_enabled(False)
        self.inspect_button.setEnabled(False)
        self.disasm_button.setEnabled(False)

        self.statusBar().showMessage("Ready")

    def set_navigation_enabled(self, enabled):
        self.jump_button.setEnabled(enabled)
        self.first_code_button.setEnabled(enabled)
        self.prev_button.setEnabled(False)
        self.next_button.setEnabled(enabled)
        self.export_button.setEnabled(enabled)

    def open_file(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, "Open Firmware Image"
        )

        if not filename:
            return

        self.backend.close()
        self.current_file = Path(filename)
        self.current_offset = 0

        try:
            size = self.current_file.stat().st_size
        except OSError as error:
            self.results.setPlainText(str(error))
            self.current_file = None
            return

        self.info_label.setText(
            f"{self.current_file.name}\n"
            f"{size:,} bytes"
        )

        self.inspect_button.setEnabled(True)
        self.disasm_button.setEnabled(True)
        self.set_navigation_enabled(False)

        self.results.setPlainText(
            f"Selected: {self.current_file}\n"
            f"Size: {size:,} bytes\n\n"
            "Choose View MIPS32 Disassembly."
        )

        self.statusBar().showMessage(
            "Firmware selected"
        )

    def inspect_file(self):
        if self.current_file is None:
            return

        try:
            with self.current_file.open("rb") as handle:
                data = handle.read(64)

            lines = []

            for offset in range(0, len(data), 16):
                chunk = data[offset:offset + 16]
                hex_values = " ".join(
                    f"{value:02X}" for value in chunk
                )

                lines.append(
                    f"{offset:08X}: {hex_values}"
                )

            self.results.setPlainText(
                f"File: {self.current_file.name}\n"
                "FIRST 64 BYTES\n\n"
                + "\n".join(lines)
            )

        except OSError as error:
            self.results.setPlainText(str(error))

    def start_disassembly(self):
        if self.current_file is None:
            return

        try:
            base = int(
                self.base_input.text().strip(), 0
            )

            self.backend.open_file(
                self.current_file, base
            )

            self.set_navigation_enabled(True)
            self.show_page(0)

        except Exception as error:
            self.set_navigation_enabled(False)
            self.results.setPlainText(
                f"Disassembly error:\n{error}"
            )
            self.statusBar().showMessage(
                "Disassembly failed"
            )

    def show_page(self, offset):
        if self.backend.session is None:
            return

        try:
            size = self.backend.file_size

            if not 0 <= offset < size:
                raise ValueError(
                    "Offset outside loaded firmware"
                )

            if offset % 4:
                raise ValueError(
                    "MIPS32 offset must be aligned "
                    "to four bytes"
                )

            address = (
                self.backend.base_address + offset
            )

            length = min(PAGE_BYTES, size - offset)

            assembly = self.backend.get_disassembly(
                address=address,
                byte_count=length,
            )

            self.current_offset = offset
            self.offset_input.setText(
                f"0x{offset:08X}"
            )

            self.results.setPlainText(
                "RYUJINWARE | RYUSECT\n"
                "MIPS32 LITTLE-ENDIAN DISASSEMBLY\n"
                f"File: {self.current_file.name}\n"
                f"Base: 0x{self.backend.base_address:08X}\n"
                f"File offset: 0x{offset:08X}\n"
                f"Virtual address: 0x{address:08X}\n"
                f"Bytes in window: {length}\n"
                f"Total file size: {size:,} bytes\n"
                + "=" * 64
                + "\n\n"
                + assembly
            )

            self.prev_button.setEnabled(
                offset > 0
            )
            self.next_button.setEnabled(
                offset + PAGE_BYTES < size
            )

            self.statusBar().showMessage(
                f"Viewing offset 0x{offset:08X}"
            )

        except Exception as error:
            self.results.setPlainText(
                f"Disassembly error:\n{error}"
            )

    def change_page(self, direction):
        offset = (
            self.current_offset
            + direction * PAGE_BYTES
        )

        offset = max(0, offset)

        if offset < self.backend.file_size:
            self.show_page(offset)

    def jump_to_offset(self):
        try:
            offset = int(
                self.offset_input.text().strip(), 0
            )

            self.show_page(offset)

        except ValueError as error:
            self.statusBar().showMessage(
                f"Invalid offset: {error}"
            )

    def find_first_nonzero(self):
        if self.backend.session is None:
            return

        offset = self.backend.find_first_nonzero()

        if offset is None:
            self.statusBar().showMessage(
                "File contains only zero bytes"
            )
            return

        self.show_page(offset)

    def export_disassembly(self):
        if self.worker is not None:
            if self.worker.isRunning():
                self.worker.requestInterruption()
                self.statusBar().showMessage(
                    "Cancelling export..."
                )
            return

        if self.backend.session is None:
            return

        suggested = (
            str(self.current_file)
            + ".mips32.disasm.txt"
        )

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Complete Disassembly",
            suggested,
            "Text Files (*.txt)"
        )

        if not filename:
            return

        self.worker = ExportWorker(
            self.current_file,
            self.backend.base_address,
            filename,
        )

        self.worker.progress.connect(
            self.progress.setValue
        )
        self.worker.completed.connect(
            self.export_completed
        )
        self.worker.failed.connect(
            self.export_failed
        )
        self.worker.finished.connect(
            self.export_finished
        )

        self.progress.setValue(0)
        self.open_button.setEnabled(False)
        self.export_button.setText("Cancel Export")
        self.worker.start()

        self.statusBar().showMessage(
            "Exporting full disassembly..."
        )

    def export_completed(self, filename):
        self.progress.setValue(100)
        self.statusBar().showMessage(
            f"Export complete: {filename}"
        )
        QMessageBox.information(
            self,
            "RyuSECT Export Complete",
            f"Full raw disassembly saved to:\n{filename}"
        )

    def export_failed(self, message):
        self.statusBar().showMessage(
            f"Export stopped: {message}"
        )
        QMessageBox.warning(
            self,
            "RyuSECT Export",
            message
        )

    def export_finished(self):
        self.export_button.setText(
            "Export Whole Disassembly"
        )
        self.open_button.setEnabled(True)
        self.worker = None

    def closeEvent(self, event):
        if (
            self.worker is not None
            and self.worker.isRunning()
        ):
            self.worker.requestInterruption()
            event.ignore()
            self.statusBar().showMessage(
                "Please wait for export to stop"
            )
            return

        self.backend.close()
        super().closeEvent(event)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    app.setStyleSheet("""
        QWidget {
            background: #101010;
            color: #D4AF37;
            font-size: 13px;
        }

        QPushButton {
            background: #183329;
            border: 1px solid #C0C0C0;
            border-radius: 6px;
            padding: 10px;
        }

        QPushButton:hover {
            background: #245440;
        }

        QPushButton:disabled {
            color: #777777;
            border-color: #444444;
        }

        QLineEdit {
            background: #080B09;
            color: #D4AF37;
            border: 1px solid #C0C0C0;
            padding: 8px;
        }

        QPlainTextEdit {
            background: #080B09;
            color: #00A86B;
            border: 1px solid #C0C0C0;
            border-radius: 6px;
        }

        QProgressBar {
            background: #080B09;
            color: #D4AF37;
            border: 1px solid #C0C0C0;
        }
    """)

    window = RyuHEX()
    window.show()

    sys.exit(app.exec())
