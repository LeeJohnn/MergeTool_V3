import argparse
from .MergeTool import MergeTool

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--toml_file_path', type = str, default = "", help="Set Toml config file path")
    args = parser.parse_args()
    toml_file_path = args.toml_file_path

    if toml_file_path:
        merge_image = MergeTool(toml_file_path)
        merge_image.exec()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()