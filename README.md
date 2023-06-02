# Código perteneciente al TFM del Máster en Ingeniería Computacional y Matemáticas 

## Métodos de aprendizaje automático aplicados a la ciberseguridad: Clasificación binaria de ejecutables del Sistema Operativo Windows.
  ***Autor: Luis Alberto Glaría Silva***  
  ***Tutor: Ángel Elbaz Sanz***
     
## Estructura del Repositorio

- `datasets/`: Aquí se encuentran los conjuntos de datos utilizados por los algoritmos. Importante: estos archivos deben guardarse en la siguiente ruta de Google Drive para poder ejecutar los cuadernos correctamente: `/content/gdrive/MyDrive/malware_datasets/`.
- `functions/`: Archivos auxiliares en Python que contienen las funciones utilizadas por la aplicación.
- `models/`: Modelos exportados de Google Colab que se utilizan en la aplicación.
- `malware_classifier_app.py`: Este es el archivo principal de la aplicación de Streamlit.

## Ejecución

Para ejecutar los cuadernos de Jupyter:

1. los conjuntos de datos deben guardarse en `/content/gdrive/MyDrive/malware_datasets/` en Google Drive.
2. Los cuadernos deben ser abiertos y ejecutados en Google Colab 

La aplicación de Streamlit está disponible en: https://glaria-tfm-malware-classifier-app-7qnhnt.streamlit.app/
Se puede ejecutar en local con Streamlit instalado ejecutando: `streamlit run malware_classifier_app.py`

## Dependencias

Ver requirements.txt (+Streamlit si se quiere ejecutar la app)

