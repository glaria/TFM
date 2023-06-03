import os
import shutil

def find_and_copy_executables(paths, destination_folder):
    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)

    for path in paths:
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith('.exe') or file.endswith('.dll'):
                    src = os.path.join(root, file)
                    dst = os.path.join(destination_folder, file)
                    try:
                        shutil.copy(src, dst)
                        print(f"Copiado {src} a {dst}")
                    except Exception as e:
                        print(f"Error al copiar archivo {src}: {str(e)}")

#rutas principales en Windows con ejecutables
windows_paths = [
    r'C:\Windows',
    r'C:\Program Files',
    r'C:\Program Files (x86)',
    r'C:\Users\34673']

destination_folder = r'C:\Users\34673\OneDrive - Universitat Oberta de Catalunya\Escritorio\Master_URV_UOC\TFM\Ciberseguridad\python_app\process_files\benign'

find_and_copy_executables(windows_paths, destination_folder)

