import os
import pefile
import csv

def extract_features(file_path):
    pe = pefile.PE(file_path)

    features = {
        'Name': os.path.basename(file_path),
        'Malware': 0, #todos los archivos son benignos
        'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
        'Characteristics': pe.FILE_HEADER.Characteristics,
        'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
        'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
        'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
        'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
        'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
        'Machine': pe.FILE_HEADER.Machine,
        'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
        'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
        'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
        'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
        'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
        'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
        'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
        'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
        'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
        'SectionMaxRawsize': max([s.SizeOfRawData for s in pe.sections]),
        'SectionMaxVirtualsize': max([s.Misc_VirtualSize for s in pe.sections]),
        'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
        'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
        'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
        'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
        'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
        'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
        'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
        'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
        'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
        'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
        'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
    }

    return features

def process_folder(folder_path, output_csv_path):
    fieldnames = [
        'Name', 'Malware', 'AddressOfEntryPoint', 'BaseOfCode', 'Characteristics', 'CheckSum', 'DllCharacteristics', 'FileAlignment',
        'ImageBase', 'LoaderFlags', 'Machine', 'MajorImageVersion', 'MajorLinkerVersion', 'MajorOperatingSystemVersion', 'MajorSubsystemVersion',
        'MinorImageVersion', 'MinorLinkerVersion', 'MinorOperatingSystemVersion', 'MinorSubsystemVersion', 'NumberOfRvaAndSizes', 'SectionAlignment',
        'SectionMaxRawsize', 'SectionMaxVirtualsize', 'SizeOfCode', 'SizeOfHeaders', 'SizeOfHeapCommit', 'SizeOfHeapReserve', 'SizeOfImage', 'SizeOfInitializedData',
        'SizeOfOptionalHeader', 'SizeOfStackCommit', 'SizeOfStackReserve','SizeOfUninitializedData', 'Subsystem'
    ]

    with open(output_csv_path, 'w', newline='') as csvfile:
        csv_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        csv_writer.writeheader()

        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    features = extract_features(file_path)
                    csv_writer.writerow(features)
                except Exception as e:
                    print(f"Error al procesar el archivo '{file_path}': {e}")

folder_path = r'C:\Users\34673\OneDrive - Universitat Oberta de Catalunya\Escritorio\Master_URV_UOC\TFM\Ciberseguridad\python_app\process_files\benign'
output_csv_path = 'benign_files_pe.csv'
process_folder(folder_path, output_csv_path)

