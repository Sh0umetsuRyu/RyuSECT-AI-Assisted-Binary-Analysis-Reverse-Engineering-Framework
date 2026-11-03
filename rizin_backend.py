
from pathlib import Path
import rzpipe


class RizinBackend:
    """RyuSECT MIPS32 raw firmware disassembly backend."""

    def __init__(self):
        self.session = None
        self.current_file = None
        self.base_address = 0
        self.file_size = 0

    def open_file(self, filename, base_address=0):
        self.close()

        path = Path(filename).resolve(strict=True)

        if not path.is_file():
            raise ValueError("Not a regular file")

        size = path.stat().st_size

        if size == 0:
            raise ValueError("Cannot open an empty file")

        if not 0 <= base_address <= 0xFFFFFFFF:
            raise ValueError("Invalid MIPS32 base address")

        if base_address % 4:
            raise ValueError("Base address must be aligned")

        if base_address + size > 0x100000000:
            raise ValueError(
                "File exceeds 32-bit mapped address space"
            )

        try:
            self.session = rzpipe.open(
                str(path),
                flags=[
                    "-n",
                    "-a", "mips",
                    "-b", "32",
                    "-m", f"0x{base_address:08x}",
                    "-e", "cfg.bigendian=false",
                ],
            )

            self.session.cmd("e scr.color=0")

            self.current_file = path
            self.base_address = base_address
            self.file_size = size

        except Exception:
            self.close()
            raise

    def get_disassembly(self, address=None, byte_count=4096):
        if self.session is None:
            raise RuntimeError("No Rizin session open")

        if address is None:
            address = self.base_address

        end = self.base_address + self.file_size

        if not self.base_address <= address < end:
            raise ValueError("Address outside binary")

        if address % 4:
            raise ValueError("Address must be 4-byte aligned")

        if not 1 <= byte_count <= 16384:
            raise ValueError("Invalid disassembly byte count")

        byte_count = min(byte_count, end - address)

        # pD disassembles a number of bytes, unlike
        # pd which disassembles a number of instructions.
        return self.session.cmd(
            f"pD {byte_count} @ 0x{address:08x}"
        )

    def get_file_info(self):
        if self.session is None:
            raise RuntimeError("No Rizin session open")

        return self.session.cmdj("ij")

    def get_hex_dump(self, count=64):
        if self.session is None:
            raise RuntimeError("No Rizin session open")

        if not 1 <= count <= 4096:
            raise ValueError("Invalid byte count")

        return self.session.cmd(
            f"px {count} @ 0x{self.base_address:08x}"
        )

    def find_first_nonzero(self):
        """Return the first nonzero file offset, aligned down."""
        if self.current_file is None:
            raise RuntimeError("No file loaded")

        offset = 0

        with self.current_file.open("rb") as handle:
            while True:
                data = handle.read(262144)

                if not data:
                    return None

                leading = len(data) - len(
                    data.lstrip(b"\x00")
                )

                if leading < len(data):
                    return (offset + leading) & ~3

                offset += len(data)

    def close(self):
        if self.session is not None:
            try:
                self.session.quit()
            except Exception:
                pass

        self.session = None
        self.current_file = None
        self.base_address = 0
        self.file_size = 0
