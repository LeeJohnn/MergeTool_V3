import struct
from .Project import ProjectInfo_Dict

class Info:
    def __init__(self, section_name: str, project_name: str, Chip_ID: int, IC_CUT: int, Key_ID: int, OTA_Enable: int, 
                 Addr_PatchStartAddress: bytes, Val_PatchStartAddress: bytes, Addr_SecurityHeaderBufferRemainSize: bytes, Val_SecurityHeaderBufferRemainSize: bytes,
                 DL_Idx: int, logger):
        """
        Section Information.
        Format:
        [1-0] Chip_ID (Range: 0x00 ~ 0xFFFF)
        [2] IC_CUT. 0 for test chip, 1 for A-cut, 2 for B-cut .... (Range: 0x00 ~ 0xFF)
        [3] Key ID (Range: 0x00 ~ 0xFF)
        [4] OTA Enable (0 or 1)
        [990-5] Reserve
        [998-991] Patch Start Address (address) -> var: rom_code_patch_start_address
        [1006-999] Patch Start Address (value)
        [1014-1007] Security Header Buffer Remain Size (address) -> var: security_header_buffer_remain
        [1022-1015] Security Header Buffer Remain Size (value)
        [1023] Download Index. Driver must reference this field to know the download sequence. (Range: 0x00 ~ 0xFF)
        """
        """
        :param section_name:
        :param project_name:
        :param Chip_ID:
        :param IC_CUT:
        :param Key_ID:
        :param OTA_Enable:
        :param Addr_PatchStartAddress:
        :param Val_PatchStartAddress:
        :param Addr_SecurityHeaderBufferRemainSize:
        :param Val_SecurityHeaderBufferRemainSize:
        :param DL_Idx:
        :param logger:
        """
        self.DL_Idx = DL_Idx

        self._section_name = section_name
        self._project_name = project_name.upper()
        self._Chip_ID = Chip_ID
        self._IC_CUT = IC_CUT
        self._Key_ID = Key_ID
        self._OTA_Enable = OTA_Enable
        self._Addr_PatchStartAddress = Addr_PatchStartAddress
        self._Val_PatchStartAddress = Val_PatchStartAddress
        self._Addr_SecurityHeaderBufferRemainSize = Addr_SecurityHeaderBufferRemainSize
        self._Val_SecurityHeaderBufferRemainSize = Val_SecurityHeaderBufferRemainSize
        self._logger = logger

        if not any(self._project_name == key for key in ProjectInfo_Dict.keys()):
            raise RuntimeError(f"{self._section_name}: The project name is not valid.")
        if not any(self._Chip_ID == value["ID"] for value in ProjectInfo_Dict.values()):
            raise RuntimeError(f"{self._section_name}: The Chip_ID is not valid.")
        if ProjectInfo_Dict[self._project_name]["ID"] != self._Chip_ID:
            raise RuntimeError(f"{self._section_name}: The project name and Chip_ID are inconsistent.")
        if self._Chip_ID > 0xFFFF or self._IC_CUT > 0xFF or self._Key_ID > 0xFF or self._OTA_Enable > 0x1 or self.DL_Idx > 0xFF:
            raise OverflowError(f"{self._section_name}: The Chip_ID or IC_CUT or Key_ID or OTA_Enable or DL_Idx is not correct.")
        if self._Addr_PatchStartAddress > 0xFFFFFFFFFFFFFFFF:
            raise OverflowError(f"{self._section_name}: The Addr_PatchStartAddress is not correct.")
        if self._Val_PatchStartAddress > 0xFFFFFFFFFFFFFFFF:
            raise OverflowError(f"{self._section_name}: The Val_PatchStartAddress is not correct.")
        if self._Addr_SecurityHeaderBufferRemainSize > 0xFFFFFFFFFFFFFFFF:
            raise OverflowError(f"{self._section_name}: The Addr_SecurityHeaderBufferRemainSize is not correct.")
        if self._Val_SecurityHeaderBufferRemainSize > 0xFFFFFFFFFFFFFFFF:
            raise OverflowError(f"{self._section_name}: The Val_SecurityHeaderBufferRemainSize is not correct.")
        
        # if self.DL_Idx == 0:
        #     if ProjectInfo_Dict[self._project_name][self._IC_CUT]["PatchStartAddress"] != 0 and \
        #         ProjectInfo_Dict[self._project_name][self._IC_CUT]["PatchStartAddress"] != self._Val_PatchStartAddress:
        #             raise RuntimeError(f"{self._section_name}: The patch start address is not valid.")
        # if self._Addr_PatchStartAddress != 0 and self._Addr_PatchStartAddress < 0xffffffff:
        #     if ProjectInfo_Dict[self._project_name][self._IC_CUT]["Addr_PatchStartAddress"] != 0 and \
        #        ProjectInfo_Dict[self._project_name][self._IC_CUT]["Addr_PatchStartAddress"] != self._Addr_PatchStartAddress:
        #         raise RuntimeError(f"{self._section_name}: The addr_patch_start_address is not valid.")
        # if self._Addr_SecurityHeaderBufferRemainSize != 0 and self._Addr_SecurityHeaderBufferRemainSize < 0xffffffff:
        #     if ProjectInfo_Dict[self._project_name][self._IC_CUT]["Addr_SecurityHeaderBufferRemainSize"] != 0 and \
        #        ProjectInfo_Dict[self._project_name][self._IC_CUT]["Addr_SecurityHeaderBufferRemainSize"] != self._Addr_SecurityHeaderBufferRemainSize:
        #         raise RuntimeError(f"{self._section_name}: The addr_security_header_buffer_remain_size is not valid.")
            
    def get_bytes(self):
        buf = bytearray()
        buf += struct.pack("<H", self._Chip_ID)
        buf.append(self._IC_CUT)
        buf.append(self._Key_ID)
        buf.append(self._OTA_Enable)
        buf += b"\x00" * 986
        buf += struct.pack("<Q", self._Addr_PatchStartAddress)
        buf += struct.pack("<Q", self._Val_PatchStartAddress)
        buf += struct.pack("<Q", self._Addr_SecurityHeaderBufferRemainSize)
        buf += struct.pack("<Q", self._Val_SecurityHeaderBufferRemainSize)
        buf.append(self.DL_Idx)
        return bytes(buf)

    def get_feature(self):
        buf = bytearray()
        buf += struct.pack("<H", self._Chip_ID)
        buf.append(self._IC_CUT)
        buf.append(self._Key_ID)
        buf.append(self._OTA_Enable)
        return bytes(buf)
    
    def get_str(self):
        self._logger.info(f"Chip_ID: {self._Chip_ID}, IC_CUT: {self._IC_CUT}, Key_ID: {self._Key_ID}, OTA_Enable: {self._OTA_Enable}")
        self._logger.info(f"DL_Idx: {self.DL_Idx}")
        self._logger.info(f"PatchStartAddress -> Addr: {hex(self._Addr_PatchStartAddress)}, Val: {hex(self._Val_PatchStartAddress)}")
        self._logger.info(f"SecurityHeaderBufferRemainSize -> Addr: {hex(self._Addr_SecurityHeaderBufferRemainSize)}, Val: {hex(self._Val_SecurityHeaderBufferRemainSize)}")
