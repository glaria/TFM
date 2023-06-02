import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
import numpy as np
from sklearn.preprocessing import StandardScaler



#lista de caracteristicas usadas por el modelo
feature_cols = ['MinorOperatingSystemVersion', 'BaseOfCode', 'SizeOfOptionalHeader',
                'SizeOfHeapCommit', 'CheckSum', 'MinorImageVersion',
                'MinorLinkerVersion', 'MajorSubsystemVersion', 'NumberOfRvaAndSizes',
                'MajorLinkerVersion', 'SizeOfUninitializedData',
                'MinorSubsystemVersion', 'SizeOfStackReserve',
                'MajorOperatingSystemVersion', 'SizeOfHeapReserve', 'SizeOfCode',
                'AddressOfEntryPoint', 'LoaderFlags', 'ImageBase',
                'SizeOfInitializedData', 'MajorImageVersion', 'SectionAlignment',
                'SizeOfHeaders', 'Subsystem', 'Characteristics', 'Machine',
                'SizeOfImage', 'FileAlignment', 'DllCharacteristics']

# Cargamos los modelos y el escalador ya entrenados
with open('models/rfc_model.pkl', 'rb') as f:
    rfc_model = pickle.load(f)

with open('models/xgb_model.pkl', 'rb') as f:
    xgb_model = pickle.load(f)

with open('models/std_scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

cols_when_model_builds = xgb_model.get_booster().feature_names

def final_prediction(X, rfc_model, xgb_model): #toma como parametros un conjunto X, un modelo random forest ya entrenado y otro modelo xgboost tambien entrenado

    X_scaled = X.to_numpy()
    #reescalamos los datos tal y como se hizo en el notebook de colab
    X_scaled = scaler.transform(X_scaled)

    rfc_proba = rfc_model.predict_proba(X)[:, 1]
    xgb_proba = xgb_model.predict_proba(X)[:, 1]

    # definimos los margenes en los que se aplicara cada modelo
    rfc_pred = rfc_proba > 0.5
    xgb_fp_pred = xgb_proba >= 0.85
    xgb_fn_pred = xgb_proba >= 0.15

    # prediccion final
    final_pred = np.where(xgb_fp_pred == xgb_fn_pred, xgb_fp_pred, rfc_pred)

    return final_pred

def evaluate_model(input_df, input_type):
    #print("Input columns: ", list(input_df.columns))
    # comprobamos si se ha cargado un csv o un ejecutable
    if input_type == 'csv':
        # Seleccionar las columnas que corresponden a las características del modelo
        features = input_df[cols_when_model_builds]
        print(input_df)
        # predicción con el modelo combinado
        predictions = final_prediction(features, rfc_model, xgb_model)
        # Añadir las predicciones al dataframe
        input_df['Malware_Flag'] = predictions
        return input_df
    elif input_type == 'exe':
        # Como solo hay un registro, seleccionamos el primer (y único) registro
        #features = input_df.loc[0, feature_cols]
        features = input_df[cols_when_model_builds]
        # Predecir con el modelo combinado
        prediction = final_prediction(features, rfc_model, xgb_model)

        # Como solo hay una predicción, devolvemos solo el primer elemento
        return int(prediction[0])
