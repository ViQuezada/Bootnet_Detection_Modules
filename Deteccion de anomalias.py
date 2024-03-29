#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Nov 27 17:36:20 2020

@author: vicente
"""

import numpy as np # linear algebra
import pandas as pd # data processing
import warnings
#import os
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from mpl_toolkits.mplot3d import Axes3D
from plotly.offline import download_plotlyjs, init_notebook_mode, plot, iplot
import chart_studio.plotly as py
from matplotlib import mpl
import plotly.graph_objs as go
import plotly.io as pio

#################################
#Funcion para graficar para cada atributo los diferentes valores que tienes las huellas
# se pinta de rojo las anomalias y azul lo limpio
def plot_anomaly(df,metric_name): 
    # Descripcion
    descrip=["P1","Numero de solicitudes DNS por hora",
            "P2","Numero de solicitudes DNS distintas por hora",
            "P3","Mayor cantidad de solicitudes para un solo dominio por hora",
            "P4","Numero medio de solicitudes por minuto",
            "P5","La mayor cantidad de solicitudes por minuto",
            "P6","Número de consultas de registros MX por hora",
            "P7","Número de consultas de registros PTR por hora",
            "P8","Número de servidores DNS distintos consultados por hora",
            "P9","Número de dominios de TLD distintos consultados por hora",
            "P10","Número de dominios SLD distintos consultados por hora",
            "P11","Relación de unicidad por hora",
            "P12","Número de consultas fallidas / NXDOMAIN por hora",
            "P13","Número de ciudades distintas de direcciones IP resueltas",
            "P14","Número de países distintos de direcciones IP resueltas",
            "P15","Relación de flujo por hora"]
    
    # para que las graficas aparezcan en el navegador, una grafica por atributo en una pestaña
    pio.renderers.default='browser' 
    #df.load_date = pd.to_datetime(df['load_date'].astype(str), format="%Y%m%d")
    dates = df.load_date
    #identify the anomaly points and create a array of its values for plot
    bool_array = (abs(df['anomaly']) > 0)
    actuals = df["actuals"][-len(bool_array):]
    anomaly_points = bool_array * actuals
    anomaly_points[anomaly_points == 0] = np.nan
    
    #opcional a la grafica de puede desglozar una tabla con todos los valores
    #donde en funcion del porcentaje de cambio de un valor con respecto al antecesor
    #se pintara deun color rojo si es un cambio fuerte, de amarillo si el leve o gris si no hay un cambio mayor
    
    #A dictionary for conditional format table based on anomaly
    #color_map = {0: "'rgba(228, 222, 249, 0.65)'", 1: "yellow", 2: "red"}
#    color_map = {0: "silver", 1: "yellow", 2: "red"}
#
#    
#    #Table which includes Date,Actuals,Change occured from previous point
#    table = go.Table(
#        domain=dict(x=[0, 1],
#                    y=[0, 0.3]),
#        columnwidth=[1, 2],
#        # columnorder=[0, 1, 2,],
#        header=dict(height=20,
#                    values=[['<b>Date</b>'], ['<b>Actual Values </b>'], ['<b>% Change </b>'],
#                            ],
#                    font=dict(color=['rgb(45, 45, 45)'] * 5, size=14),
#                    fill=dict(color='#d562be')),
#        cells=dict(values=[df.round(3)[k].tolist() for k in ['load_date', 'actuals', 'percentage_change']],
#                   line=dict(color='#506784'),
#                   align=['center'] * 5,
#                   font=dict(color=['rgb(40, 40, 40)'] * 5, size=12),
#                   # format = [None] + [",.4f"] + [',.4f'],
#                   # suffix=[None] * 4,
#                   suffix=[None] + [''] + [''] + ['%'] + [''],
#                   height=27,
#                   fill=dict(color=[test_df['anomaly_class'].map(color_map)],#map based on anomaly level from dictionary
#                   )
#                   ))
    #print(table)
    #Plot the actuals points
    
    #valores catalogados como limpios
    Actuals = go.Scatter(name='Limpio',
                         x=dates,
                         y=df['actuals'],
                         xaxis='x1', yaxis='y1',
                         mode='markers',
                         marker=dict(size=5,
                                     line=dict(width=1),
                                     color="blue"))
#Highlight the anomaly points
#valores catalogados cmo anomalias
    anomalies_map = go.Scatter(name="Bot",
                               showlegend=True,
                               x=dates,
                               y=anomaly_points,
                               mode='markers',
                               xaxis='x1',
                               yaxis='y1',
                               marker=dict(color="red",
                                           size=5,
                                           line=dict(
                                               color="red",
                                               width=1)))
    #print(anomalies_map)
    # atributos de las graficas a obtener
    axis = dict(
            showline=True,
            zeroline=False,
            showgrid=True,
            mirror=True,
            ticklen=4,
            gridcolor='#ffffff',
            tickfont=dict(size=10))
    layout = dict(
            width=1000,
            height=865,
            autosize=True,
            #title=metric_name+": "+descrip[descrip.index(metric_name)+1],
            margin=dict(t=75),
            showlegend=True,
            xaxis1=dict(axis, **dict(domain=[0, 1], anchor='y1', showticklabels=True)),
            yaxis1=dict(axis, **dict(domain=[2 * 0.21 + 0.20, 1], anchor='x1', hoverformat='.2f')))
    
    #graficar
    fig = go.Figure(data=[Actuals,anomalies_map], layout=layout)
    fig.update_yaxes(type="log")
    iplot(fig)
    #pyplot.show()

#cladificar anomalias, para graficar la tabla de cambio, alto leve o nulo.
#0 normal(gris), 1 anomalia baja(amarillo) y 2 anomalia alta(rojo)
def classify_anomalies(df,metric_name):
    df['metric_name']=metric_name
    df = df.sort_values(by='load_date', ascending=False)
    #Shift actuals by one timestamp to find the percentage chage between current and previous data point
    df['shift'] = df['actuals'].shift(-1)
    df['percentage_change'] = ((df['actuals'] - df['shift']) / df['actuals']) * 100
    #Categorise anomalies as 0-no anomaly, 1- low anomaly , 2 - high anomaly
    df['anomaly'].loc[df['anomaly'] == 1] = 0
    df['anomaly'].loc[df['anomaly'] == -1] = 2
    df['anomaly_class'] = df['anomaly']
    max_anomaly_score = df['score'].loc[df['anomaly_class'] == 2].max()
    medium_percentile = df['score'].quantile(0.24)
    df['anomaly_class'].loc[(df['score'] > max_anomaly_score) & (df['score'] <= medium_percentile)] = 1
    return df

##################################

warnings.filterwarnings('ignore')
#print(os.listdir("../Tesis"))

#inicia el programa
#leer el csv de huellas digitales obtenido
df=pd.read_csv("/home/vicente/Escritorio/Tesis/fingerprints.csv")
df.head()
metrics_df=df
print("numero de host: ",len(set(metrics_df['ip']))) # saber cuantos host distintos existen

#definir las columnas con las cuales se va a entrenar el algoritmo
metrics_df.columns
to_model_columns=metrics_df.columns[3:18] 
#clf=IsolationForest(n_estimators=100, max_samples='auto', contamination=float(.12),
                    #max_features=1.0, bootstrap=False, n_jobs=-1, random_state=42, 
                    #verbose=0)
#definir el algoritmo de isolation forest con 110 arboles y entrenar
clf=IsolationForest(n_estimators=110, max_samples='auto', contamination='auto',
                    max_features=1.0, bootstrap=False, n_jobs=-1, random_state=42, 
                    verbose=0) #valores para el algoritmo de isolation forest
clf.fit(metrics_df[to_model_columns])
pred= clf.predict(metrics_df[to_model_columns]) # predecir anomalias
metrics_df['anomaly']=pred
outliers=metrics_df.loc[metrics_df['anomaly']==-1]
outlier_index=list(outliers.index)
#print(outlier_index)
#Find the number of anomalies and normal points here points classified -1 are anomalous
print(metrics_df['anomaly'].value_counts())

 # Reduce to k=3 dimensions para poder graficar y observar
 # esta grafica es completa
pca = PCA(n_components=3) 
scaler = StandardScaler()
#normalize the metrics
X = scaler.fit_transform(metrics_df[to_model_columns])
X_reduce = pca.fit_transform(X)
fig = plt.figure()
fig.suptitle('Huellas_DNS_3D')
ax = fig.add_subplot(111, projection='3d')
# Plot the compressed data points
ax.scatter(X_reduce[:, 0], X_reduce[:, 1], X_reduce[:, 2], s=4, lw=1, label="normal",c="green")
# Plot x's for the ground truth outliers
ax.scatter(X_reduce[outlier_index,0],X_reduce[outlier_index,1], X_reduce[outlier_index,2],
           lw=1, s=4, c="red", label="anormal")
ax.legend()

plt.show()

# Reduce to k=3 dimensions
# esta grafica escala los ejes con el fin de hacer un acercamiento a la zona de mayor concetracion de valores
pca = PCA(n_components=3)  
scaler = StandardScaler()
#normalize the metrics
X = scaler.fit_transform(metrics_df[to_model_columns])
X_reduce = pca.fit_transform(X)
fig = plt.figure()
fig.suptitle('Huellas_DNS_3D')
ax = fig.add_subplot(111, projection='3d')
# Plot the compressed data points
ax.scatter(X_reduce[:, 0], X_reduce[:, 1], X_reduce[:, 2], s=4, lw=1, label="normal",c="green")
# Plot x's for the ground truth outliers
ax.scatter(X_reduce[outlier_index,0],X_reduce[outlier_index,1], X_reduce[outlier_index,2],
           lw=1, s=4, c="red", label="anormal")
ax.legend()
ax.set_zlim3d(-10,5)
ax.set_xlim3d(-3,4)
ax.set_ylim3d(0,4)
#ax.axis('off')
plt.show()

# reduccion a 2 componentes para graficar y observar
plt.figure()
pca = PCA(2) 
pca.fit(metrics_df[to_model_columns])
res=pd.DataFrame(pca.transform(metrics_df[to_model_columns]))
Z = np.array(res)
plt.title("Huellas_DNS_2D")
plt.contourf( Z, cmap=plt.cm.Blues_r)
b1 = plt.scatter(res[0], res[1], c='green',
                 s=20,label="normal")
b1 =plt.scatter(res.iloc[outlier_index,0],res.iloc[outlier_index,1], c='red',
                s=20,label="anormal")
plt.legend(loc="upper right")
plt.show()

####
#generar un nuevo dataset con las huellas pero esta vez catalogadas, 1 normal, -1 anormal
metrics_df.to_csv(r'FP_anomalies_target.csv',index=False) 

# comunicacioncon elasticsearch
from elasticsearch import Elasticsearch
import pandas as pd
import socket
import socks
import numpy as np
ii = 1
def Convert(a):
    it = iter(a)
    res_dct = dict(zip(it, it))
    return res_dct

#conexion a elasticsearch
socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
socket.socket = socks.socksocket

try:
  es = Elasticsearch([{'host':'172.17.1.73','port':9200,}])
  print ("Connected")
except Exception as ex:
  print ("Error:", ex)
  
try:
    res=es.indices.delete(index='huellas_catalogadas')
except:
    pass

#aparte del dataset obtenido en csv se suben los datos a elasticsearch para poder analizarlos
datos_finales=[["@timestamp",time,
                "ip",ip,"p1",p1,"p2",p2,"p3",p3,"p4",p4,"p5",p5,
                "p6",p6,"p7",p7,"p8",p8,"p9",p9,"p10",p10,"p11",
                p11,"p12",p12,"p13",p13,"p14",p14,"p15",p15,"an",an] 
                for time,ip,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,an 
                in zip(metrics_df['@timestamp'],metrics_df['ip'],metrics_df['P1'],metrics_df['P2'],metrics_df['P3'],
        metrics_df['P4'],metrics_df['P5'],metrics_df['P6'],metrics_df['P7'],metrics_df['P8'],metrics_df['P9'],
        metrics_df['P10'],metrics_df['P11'],metrics_df['P12'],metrics_df['P13'],metrics_df['P14'],metrics_df['P15'],
        metrics_df['anomaly'])]
 
 #convertir los datos de array a tipo JSON y subir a elasticsearch
datos_finales_json=[Convert(item) for item in datos_finales]
    
for item in datos_finales_json:
    res=es.index(index='huellas_catalogadas',doc_type='huellas_catalogadas',id=ii,body=item)
    ii=ii+1
####
init_notebook_mode(connected=True)
warnings.filterwarnings('ignore')

###
#columna_indice=[i for i in range(len(metrics_df))]
#metrics_df['index']=columna_indice
###

# diferentes graficas de las huellas catalogadas obtenidas para ingresarlas en la teoria
# las funciones de las graficas estan al inicio de este documento
for i in range(3,len(metrics_df.columns)-1):
    clf.fit(metrics_df.iloc[:,i:i+1])
    pred = clf.predict(metrics_df.iloc[:,i:i+1])
    test_df=pd.DataFrame()

    test_df['load_date']=metrics_df['index']
    #Find decision function to find the score and classify anomalies
    test_df['score']=clf.decision_function(metrics_df.iloc[:,i:i+1])
    test_df['actuals']=metrics_df.iloc[:,i:i+1]
    test_df['anomaly']=pred
    #Get the indexes of outliers in order to compare the metrics     with use case anomalies if required
    outliers=test_df.loc[test_df['anomaly']==-1]
    outlier_index=list(outliers.index)
    test_df=classify_anomalies(test_df,metrics_df.columns[i])
    plot_anomaly(test_df,metrics_df.columns[i])
     
