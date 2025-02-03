from datetime import datetime
from io import StringIO
from .Information import Info
import logging
import os
from .PatchImageSection import PatchImageSection
import struct
import toml


class MergeTool:
    def __init__(self, toml_file_path: str) -> None:
        self.toml_file_path = toml_file_path
        # This is a container for storing final binary file
        self._merge_patch_buf = bytearray()
        self._version_timestamp = datetime.now()
        self._git_version = ""
        self._logStream = StringIO()
        self._export_folder_path = "Export/"
        self._export_filename = ""
        # Used to check that the same [project_id,ic_cut,key_id,ota_enable]
        # cannot have different opcodes or same index.
        self._info_features_dict = {}
        # Used to sort the sections by download index and
        # [project_id,ic_cut,key_id,ota_enable]
        self._section_dict = {}

        # Load config
        try:
            self._top_level_config = toml.load(self.toml_file_path)
        except FileNotFoundError:
            raise FileNotFoundError(
                f"Config file does not exist: {self.toml_file_path}")

        # Create export file if it does not exist
        self.__create_export_dir_if_not_exist()

        # Initiate timestamp
        self.__replace_timestamp_if_manually_setting_on()

        # Initiate logger
        self.__logger_init()
        self._logger = logging.getLogger("MergeTool")

    def __logger_init(self) -> None:
        logging.basicConfig(
            stream=self._logStream,
            format="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            level=logging.DEBUG
        )

    def __create_export_dir_if_not_exist(self) -> None:
        if not os.path.exists(self._export_folder_path):
            # directory not exist
            os.mkdir(self._export_folder_path)

    def __replace_timestamp_if_manually_setting_on(self) -> None:
        config = self._top_level_config["MergePatchImage"]
        if not config["auto_update_version"]:
            timestamp_cfg = config["manually_set_timestamp"]
            if isinstance(timestamp_cfg, datetime):
                self._version_timestamp = timestamp_cfg
            else:
                raise RuntimeError(
                    "manually_set_timestamp field is not a correct timestamp format")

    def __export_filename_setup(self) -> None:
        # file name pattern:
        # bt_fw_asic_rom_patch_{year}{month}{day}{hour}{minute}{second}
        section = self._top_level_config["Section"]
        section_0 = section["Section_0"]
        project_name = section_0["project_name"]

        timestamp = self._version_timestamp
        year_str = str(timestamp.year).zfill(4)
        month_str = str(timestamp.month).zfill(2)
        day_str = str(timestamp.day).zfill(2)
        hour_str = str(timestamp.hour).zfill(2)
        minute_str = str(timestamp.minute).zfill(2)
        second_str = str(timestamp.second).zfill(2)
        self._export_filename = f"{project_name.lower()}_bt_fw_asic_rom_patch_{year_str}{month_str}{day_str}_{hour_str}{minute_str}{second_str}"

        version_mdhms = hex(
            timestamp.month *
            100000000 +
            timestamp.day *
            1000000 +
            timestamp.hour *
            10000 +
            timestamp.minute *
            100 +
            timestamp.second).upper()[
            2:]
        if len(version_mdhms) < 8:
            version_mdhms = '0' + version_mdhms
        self._export_filename += f"_0x{version_mdhms[:4]}_{version_mdhms[4:]}_git_{self._git_version}"

    def exec(self) -> None:
        config = self._top_level_config["MergePatchImage"]
        if config["rule_version"] == 3:
            self.__exec_merge_rule_v3()
        else:
            raise RuntimeError("The rule_version is invalid.")
        # Initiate export filename
        self.__export_filename_setup()
        self.__save_bin_and_log()
        self.__gen_c_file()

    def __exec_merge_rule_v3(self) -> None:
        section_config = self._top_level_config["Section"]
        timestamp = self._version_timestamp
        logger = self._logger

        logger.info(f"Merge patch format version: 3")

        # Append signature "BTNIC003"
        signature_buf = bytes.fromhex("42 54 4e 49 43 30 30 33")
        self._merge_patch_buf += signature_buf

        # Append timestamp version (Year/Month/Day part)
        logger.info("Version:")
        version_ymd = timestamp.year * 10000 + timestamp.month * 100 + timestamp.day
        version_ymd_buf = struct.pack("<I", version_ymd)
        self._merge_patch_buf += version_ymd_buf
        logger.info(
            f"  Year/Month/Day part: 0x{version_ymd_buf.hex()} ({version_ymd})")

        # Append timestamp version (Hour/Minute/Second part)
        version_hms = timestamp.hour * 10000 + timestamp.minute * 100 + timestamp.second
        version_hms_buf = struct.pack("<I", version_hms)
        self._merge_patch_buf += version_hms_buf
        logger.info(
            f"  Hour/Minute/Second part: 0x{version_hms_buf.hex()} ({version_hms})")

        # rsvd
        self._merge_patch_buf += b"\x00" * 4

        # Append num of sections 4 byte
        num_of_sections = len(section_config)
        num_of_sections_buf = struct.pack("<I", num_of_sections)
        self._merge_patch_buf += num_of_sections_buf
        logger.info(f"Numbers of section: {num_of_sections}")

        # Append each enabled sections
        for section in section_config:
            logger.info(f"Start {section} section process")
            if section_config[section]['opcode'] == 1:
                self.__exec_opcode_1(section)
            else:
                raise RuntimeError(f"The opcode in {section} is invalid.")

        logger.info("Sort the sections")

        sorted_data = {
            key: sorted(value, key=lambda x: x[0])
            for key, value in self._section_dict.items()
        }

        for key, value in sorted_data.items():
            feature = list(struct.unpack('<IHBBB', key))
            logger.info(f"Opcode: {feature[0]}")
            logger.info(
                f"Chip_ID: {feature[1]}, IC_CUT: {feature[2]}, Key_ID: {feature[3]}, OTA_Enable: {feature[4]}")
            for data in value:
                logger.info(f"  -> DL_Idx: {data[0]}")
                self._merge_patch_buf += data[1]

    def __exec_opcode_1(self, section_name) -> None:
        info_data, info_feature, index = self.__gen_information_field(
            section_name)

        section_config = self._top_level_config["Section"]
        section = PatchImageSection(
            section_name,
            section_config[section_name]['opcode'],
            info_data,
            section_config[section_name]['path'],
            self._logger.getChild(section_name))
        section_data = section.get_bytes()

        if self._git_version == "":
            git_version_u32 = struct.unpack("<I", section_data[-8:-4])[0]
            self._git_version = f"{git_version_u32:08x}"
            timestamp = self._version_timestamp
            version_mdhms = timestamp.month * 100000000 + timestamp.day * 1000000 + \
                timestamp.hour * 10000 + timestamp.minute * 100 + timestamp.second
            version_mdhms_buf = struct.pack("<I", version_mdhms)
            section_data = bytearray(section_data)
            section_data[-4:] = version_mdhms_buf
            section_data = bytes(section_data)

        opcode = section.opcode
        self.__check_information_field(
            section_name, opcode, index, info_feature)

        section_key = struct.pack("<I", opcode) + info_feature

        if section_key not in self._section_dict.keys():
            self._section_dict[section_key] = [[index, section_data]]
        else:
            self._section_dict[section_key].append([index, section_data])

        section.get_str()

    def __gen_information_field(self, section_name):
        section_config = self._top_level_config["Section"]

        # Only rtl8822e requires ota function
        if section_config[section_name]['project_name'].lower(
        ) == 'rtl8822e' or section_config[section_name]['ic_cut'] == 33:
            ota_enable = 1
        else:
            ota_enable = 0

        information = Info(section_name, section_config[section_name]['project_name'],
                           section_config[section_name]['project_id'],
                           section_config[section_name]['ic_cut'],
                           section_config[section_name]['key_id'],
                           ota_enable,
                           section_config[section_name]['addr_patch_start_address'],
                           section_config[section_name]['val_patch_start_address'],
                           section_config[section_name]['addr_security_header_buffer_remain_size'],
                           section_config[section_name]['val_security_header_buffer_remain_size'],
                           section_config[section_name]['index'],
                           self._logger.getChild(section_name))

        info_data = information.get_bytes()
        info_feature = information.get_feature()
        index = information.DL_Idx
        information.get_str()

        return info_data, info_feature, index

    def __check_information_field(
            self, section_name, opcode, index, info_feature) -> None:
        if info_feature not in self._info_features_dict.keys():
            self._info_features_dict[info_feature] = [[opcode], [index]]
        else:
            if self._info_features_dict[info_feature][0][0] != opcode:
                raise RuntimeError(
                    f"{section_name}: The images with the same [project_id,ic_cut,key_id,ota_enable] have different opcodes. This is invalid.")
            if index not in self._info_features_dict[info_feature][1]:
                self._info_features_dict[info_feature][1].append(index)
            else:
                raise RuntimeError(
                    f"{section_name}: The images with the same [project_id,ic_cut,key_id,ota_enable] have the same download index. This is invalid.")

        if len(self._info_features_dict[info_feature][1]) > 64:
            raise RuntimeError(
                f"{section_name}: The sum of the images with the same [project_id,ic_cut,key_id,ota_enable] exceeds 64. This is invalid.")

    def __save_bin_and_log(self) -> None:
        bin_file_path = self._export_folder_path + self._export_filename + ".bin"
        log_file_path = self._export_folder_path + self._export_filename + ".log"

        with open(bin_file_path, mode="wb+") as fp:
            fp.write(self._merge_patch_buf)

        with open(log_file_path, mode="w+") as fp:
            fp.write(self._logStream.getvalue())

    def __gen_c_file(self) -> None:

        c_file_format_config = self._top_level_config["CFileFormat"]
        if c_file_format_config["file_name"] == "":
            c_filename = self._export_filename + ".c"
        else:
            c_filename = c_file_format_config["file_name"]
        c_file_path = self._export_folder_path + c_filename
        array_var_name = c_file_format_config["array_var_name"]
        array_len_var_name = c_file_format_config["array_len_var_name"]

        c_code = self.bytes_to_C_code_string(
            self._merge_patch_buf,
            self._export_filename,
            self._version_timestamp,
            array_var_name,
            array_len_var_name)
        with open(c_file_path, mode="w+") as fp:
            fp.write(c_code)

    def chunks(self, lst, n):
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(lst), n):
            yield lst[i:i + n]

    def bytes_to_C_code_string(self, bytes_arr, filename: str,
                               timestamp: datetime, arr_var_name: str, arr_len_var_name: str):
        timestamp_num = (timestamp.year - 2010) * 1000000 + \
            timestamp.month * 10000 + timestamp.day * 100 + timestamp.hour
        version_start_index = filename.find("0x")
        lmp_version_be = hex(
            int(filename[version_start_index + 7: version_start_index + 11], 16))
        hci_version = hex(
            int(filename[version_start_index + 2: version_start_index + 6], 16))
        if len(hci_version) < 6:
            hci_version = hci_version[:2] + '0' + hci_version[2:]
        file_str = f"""
/**
 *******************************************************************************
 * Copyright(c) {timestamp.year}, Realtek Semiconductor Corporation. All rights reserved.
 *******************************************************************************
 * @file {filename}.bin
 * @date {timestamp.year}-{str(timestamp.month).zfill(2)}-{str(timestamp.day).zfill(2)} {str(timestamp.hour).zfill(2)}:{str(timestamp.minute).zfill(2)}
 * @meta HCI ver: 0x{hci_version.upper()[2:]}, LMP ver: 0x{lmp_version_be.upper()[2:]}
 */
const unsigned char {arr_var_name}[] = {{
"""
        b_collection = ""
        lines = self.chunks(bytes_arr, 16)
        for line in lines:
            line_str = "    "
            for B in line:
                B_str = struct.pack("<B", B).hex().upper().zfill(2)
                line_str += f"0x{B_str}, "
            b_collection += line_str
            b_collection += "\n"

        b_collection = b_collection.rstrip(", \n")

        file_str += b_collection
        file_str += f"""
}};

unsigned int {arr_len_var_name} = sizeof({arr_var_name});
"""
        return file_str
