v#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jan 15 20:55:45 2021

@author: vicente
"""

import pandas as pd
import datetime
import consultas
import socket
import socks
import requests
from elasticsearch import Elasticsearch
from collections import Counter
import statistics
import math
import numpy as np
from tabulate import tabulate
from termcolor import colored

#definir vocales y consonantes, la y es considerada una vocal segun la teoria
voc=["a","e","i","o","u","y","A","E","I","O","U","Y"]
cons=["b","c", "d", "f", "g", 
             "h", "j", "k", "l", "m", 
             "n", "ñ", "p", "q", "r", 
             "s", "t", "v", "w", "x", "z",
             "B","C", "D", "F", "G", 
             "H", "J", "K", "L", "M", 
             "N", "Ñ", "P", "Q", "R", 
             "S", "T", "V", "W", "X", "Z"]

# funcion dnde los parametros de RMA catalogan si es bot o limpio
def rma(ln,max_cons,max_voc,entropia):
    if (entropia <= 2) and (ln<5):
        categoria="limpio"
    elif (entropia>3.24):
        categoria="bot"
    elif (max_cons >= 4) or (max_voc >=4):
        categoria="bot"
    else:
        categoria="limpio"
    return(categoria)

#funcion para obtener el numero de vocales y consonantes, 
#asi como el numero maximo de vocales y consonantes consecutivas
def obtener_metricas(palabra):
    max_voc=0
    max_cons=0
    con_voc=0
    con_cons=0
    
    ln = len(palabra)
    
    l_ant="n"
    for letra in palabra:
        if letra in voc:
            if l_ant=="c":
                if (con_cons > max_cons):
                    max_cons=con_cons
                con_cons=0
            con_voc=con_voc+1 
            l_ant="v"
        elif letra in cons:
            if l_ant=="v":
                if (con_voc > max_voc):
                    max_voc=con_voc
                con_voc=0
            con_cons=con_cons+1
            l_ant="c"
        else:
            if l_ant=="c":
                if (con_cons > max_cons):
                    max_cons=con_cons
                con_cons=0
            elif l_ant=="v":
                if (con_voc > max_voc):
                    max_voc=con_voc
                con_voc=0
            l_ant="n"
    
    if l_ant=="c":
        if (con_cons > max_cons):
            max_cons=con_cons
    elif l_ant=="v":
        if (con_voc > max_voc):
            max_voc=con_voc
    
    #para sacar la entropia de una palabra, considerando la longitud, las letras y probabilidad
    num_elem = len(palabra)
    prob_elem = 1/num_elem
    elem_set = set(palabra)
    c_pro_elem = []
    for elemento in elem_set:
        c_pro_elem.append(palabra.count(elemento))
    f_pro=[i*prob_elem for i in c_pro_elem]
    entropia=0
    for prob in f_pro:
        entropia=entropia+(prob*math.log(prob,2))
    entropia=round(entropia*(-1),2)
    return(ln,max_cons,max_voc,entropia)
#
#conexion con elasticsearch 
socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
socket.socket = socks.socksocket

try:
  es = Elasticsearch([{'host':'172.17.1.73','port':9200,}])
  print ("Connected")
except Exception as ex:
  print ("Error:", ex)
  
HEADERS = {
        'Content-Type': 'application/json'
        }

## quitar elementos
"""
lista_blanca=["200.0.29.68",
              "45.182.117.5",
              "186.3.44.231",
              "201.159.222.92",
              "181.198.63.86",
              "2800:0068:0000:bebe:0000:0000:0000:0004"]

df=pd.read_csv("/home/vicente/Escritorio/Tesis/FP_anomalies_target.csv")
df.head()
metrics_df=df
for item in lista_blanca:
    metrics_df=metrics_df.loc[metrics_df['ip']!=item]

long=len(metrics_df)
valores=range(1,long+1)
metrics_df['index']=valores

metrics_df.to_csv(r'FP_anomalies_target1.csv',index=False)
"""
#cargar archivo de huellas catalogadas
metrics_df=pd.read_csv("../Tesis/FP_anomalies_target1.csv")
outliers=metrics_df.loc[metrics_df['anomaly']==-1] # obtener las huellas anomalas

print("numero de huellas infectadas:",len(outliers))
print("numero de hosts infectados:",len(set(outliers['ip'])))
print("Veces que los host han sido catalogados:")
a=Counter(outliers['ip'])
a=dict(a)

#valores minimos maximos y promedios de los host con anomalias, 
#de las veces que una de sus huellas a sido catalogada como anomala
print("minimo de veces detectado:",min(a.values()))
print("maximo de veces detectado:",max(a.values()))
print("promedio de veces detectado:",statistics.mean(a.values()))

salida = open("dominios_dga.txt", "w") #crear un archivo con los dominos dga de cada huellas detectada
for item in outliers['index']:
    #obtener ip, gte y lte, para buscar los dominos consultados por esa ip en el trascurso de esa hora
    ip_time=[metrics_df['ip'][item-1],metrics_df['@timestamp'][item-1]]
    
    gte=datetime.datetime.strptime(ip_time[1],'%Y-%m-%dT%H:%M:%SZ')
    lte=(gte+datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")   
    indice="logstash-dns-"+gte.strftime("%Y.%m.%d")
    uri = "http://172.17.1.73:9200/"+indice+"/_search"
    
    query=consultas.sentencia_pNX0(ip_time[0],gte.strftime("%Y-%m-%dT%H:%M:%SZ"),lte)
    r = requests.get(uri,headers=HEADERS, data=query).json()
    num_sitios=r["aggregations"]["Filtro_type"]["Filtro_ip"]["unique_ids"]["value"]
    if num_sitios>65000:
        num_sitios=65000
    if num_sitios!=0:       
        query=consultas.sentencia_pNX(ip_time[0],num_sitios,gte.strftime("%Y-%m-%dT%H:%M:%SZ"),lte)
        r = requests.get(uri,headers=HEADERS, data=query).json()
        P9_1=[item['key'].rsplit(sep='.',maxsplit=2) for item in r["aggregations"]["Filtro_type"]["Filtro_ip"]["Filtro_NX"]["Filtro_dls"]["buckets"]]
        sitios=[row[1]+"."+row[2] if len(row)>2 else row[0]+"."+row[1] if len(row)==2 else row[0] for row in P9_1]
        sitios=set(sitios)
    
    #contar bo
    #ii=0;
    #con los sitios se procede a analizar cada sitio y de ser dga se exribira en el archivo de texto
    #antes habra un encabezado de la ip y la hora a la que el sitio fue consultado
    sitios_dga=[]
    salida.write(metrics_df['ip'][item-1]+metrics_df['@timestamp'][item-1]+"\n")
    #print(colored(metrics_df['ip'][item-1],"red"),colored(metrics_df['@timestamp'][item-1],"red"))
    #sitios_dga.append(metrics_df['ip'][item-1])
    for item1 in sitios:
        if item1!="":
            sit=item1.rsplit(sep=".",maxsplit=2)[0]
            metricas = obtener_metricas(sit)
            v_rma = rma(metricas[0],metricas[1],metricas[2],metricas[3])
            if (v_rma=="bot"):
                sitios_dga.append(item1)
                #ii+=1
                #print(ii,metrics_df['ip'][item-1],item1,metricas[3])
    #print(metricas,v_rma)
    #print(sitios_dga)
    salida.write(str(sitios_dga)+"\n")
              
salida.close()
