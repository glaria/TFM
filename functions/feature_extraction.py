import pefile
"""
Funciones para la extracción de características de archivos ejecutables de windows

"""
def extract_features(file, file_name):
    with open(file, "rb") as file_content:
        pe= pefile.PE(data=file_content.read(), fast_load=True)

    features = {
        'Name': file_name,  # Aquí cambiamos os.path.basename(file) por el nombre del archivo que recibimos como parametro
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

#esta funcion devuelve solo aquellas caracteristicas que estan en cierta lista, 
# en nuestro caso es la lista de características usadas en el entrenamiento
def select_features(features_dict, feature_list):
    selected_features = {k: v for k, v in features_dict.items() if k in feature_list}
    return selected_features
