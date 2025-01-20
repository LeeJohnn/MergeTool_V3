import struct
import os

class PatchImageSection:
    def __init__(self, section_name, opcode, info, path, logger):
        self.opcode = opcode

        self._section_name = section_name
        self._info = info
        self._path = path
        self._logger = logger

        if self.opcode > 0xFFFF:
            raise OverflowError(f"{self._section_name}: The information field is not correct.")
    
        if not os.path.exists(self._path):
            raise FileNotFoundError(f"{self._section_name}: The patch image file does not exist: {self._path}")
        
        with open(self._path, mode="rb") as fp:
            patch_image_payload = fp.read()
        self._payload = bytearray(patch_image_payload)

        if len(self._payload) > 0xFFFFFFFFFFFFFFFF:
            raise OverflowError(f"{self._section_name}: The image payload length is not correct.")
        
        self._image_len = struct.pack("<Q", len(self._payload))

    def get_bytes(self):
        buf = bytearray()
        # Section opcode
        buf += struct.pack("<I", self.opcode)
        # Section length
        section_payload_len = len(self._info) + len(self._image_len) + len(self._payload)
        buf += struct.pack("<Q", section_payload_len)
        # Section payload
        buf += self._info
        buf += self._image_len
        buf += self._payload
        return bytes(buf)
    
    def get_str(self) -> None:
        self._logger.info(f"Image Length: {len(self._payload)}")
        self._logger.info(f"Opcode: {self.opcode}, Section Payload Length: {len(self._info) + len(self._image_len) + len(self._payload)}")