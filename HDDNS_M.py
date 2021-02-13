#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Oct  6 09:55:19 2020

@author: vicente
"""

import requests
from elasticsearch import Elasticsearch
from statistics import mean
import pandas as pd
import datetime
import os
import socket
import socks
import consultas
import numpy as np

lista_blanca_ips=[
        "201.159.221.68",
        "192.207.244.250"
        ]

def convertir_tiempo(tiempo):
    return(tiempo.strftime("%Y-%m-%dT%H:%M:%SZ"))
    
def Convert(a):
    it = iter(a)
    res_dct = dict(zip(it, it))
    return res_dct

socks.set_default_proxy(socks.SOCKS5, "localhost", 9000)
socket.socket = socks.socksocket

try:
  es = Elasticsearch([{'host':'172.17.1.73','port':9200,}])
  print ("Connected")
except Exception as ex:
  print ("Error:", ex)

#ver los indices dns existentes
indices_dns=[]
for index in es.indices.get('logstash-*'):
  indices_dns.append(index)
print(indices_dns)

try:
    res=es.indices.delete(index='fingerprints')
except:
    pass

try:
    os.remove("fingerprints.csv")
except:
    pass

try:
    os.remove("num_host.csv")
except:
    pass

ii = 1
indexs=1

matriz_num_host=[]
for indice in indices_dns:
    numero_hosts=[]        
    fecha=indice[13:24]
    t1=datetime.datetime(
            int(fecha.split(".")[0]),
            int(fecha.split(".")[1]),
            int(fecha.split(".")[2]),
            00,00,00)
    
    horas=[]
    for i in range(24):
        horas.append(t1+datetime.timedelta(hours=i))
    
    for item_horas in horas:
        gte=convertir_tiempo(item_horas)
        lte=convertir_tiempo(item_horas+datetime.timedelta(hours=1))
        
        HEADERS = {
        'Content-Type': 'application/json'
        }
        uri = "http://172.17.1.73:9200/"+indice+"/_search"

        #numero de host por hora
        query=consultas.sentencia_p1_1(gte,lte)
        r = requests.get(uri,headers=HEADERS, data=query).json()
        num_host=r["aggregations"]["Filtro_type"]["num_hosts"]["value"]
        numero_hosts.append(num_host)
        
        if num_host!=0:
            #Num solicitudes dns por hora para cada host
            #Considerando que cada host a hecho un minimo de 100 solicitudes
            query=consultas.sentencia_p1(num_host,gte,lte)
            r = requests.get(uri,headers=HEADERS, data=query).json()
            ips=[]
            P1=[] 
            for item in r["aggregations"]["Filtro_type"]["sacar_ip"]["buckets"]:
                if (item['key'] in lista_blanca_ips) == False:
                    ips.append(item['key'])
                    P1.append(item['doc_count'])
                
            P1_1=[]
            for i in range(len(P1)):
                P1_1.append(gte)
            
            P2=[]#numeros de solicitudes dns sitintas por hora
            for item in ips:
                query=consultas.sentencia_p2(item,gte,lte)
                r = requests.get(uri,headers=HEADERS, data=query).json()
                P2.append(r["aggregations"]["Filtro_type"]["Filtro_ip"]["unique_ids"]["value"])
            
            P3=[]#max de solicitudes para un solo dominio
            for item,item2 in zip(ips,P2):
                P4_1=[]
                query=consultas.sentencia_p3(item,item2,gte,lte)
                r = requests.get(uri,headers=HEADERS, data=query).json()
                if r["aggregations"]["Filtro_type"]["Filtro_ip"]["dnss"]["buckets"] != []:
                    P3.append(r["aggregations"]["Filtro_type"]["Filtro_ip"]["dnss"]["buckets"][0]["doc_count"])
                else:
                    P3.append(0)
               
            P4=[]#media de solicitudes por minuto
            P5=[]#mayor cantidad de solicitudes por minuto
            for item  in ips:
                P4_1=[]
                query=consultas.sentencia_p4(item,gte,lte)
                r = requests.get(uri,headers=HEADERS, data=query).json()
                if r["aggregations"]["Filtro_type"]["Filtro_ip"]["tiempos"]["buckets"]!=[]:       
                    P4_1=[item1['doc_count'] for item1 in r["aggregations"]["Filtro_type"]["Filtro_ip"]["tiempos"]["buckets"]]
                    P4.append(round(mean(P4_1),4))
                    P5.append(max(P4_1))
                else:
                    P4.append(0)
                    P5.append(0)    
                
            P6=[]#MX por hora
            for item in ips:
                query=consultas.sentencia_p6(item,gte,lte)
                r = requests.get(uri,headers=HEADERS, data=query).json()
                P6.append(r["aggregations"]["Filtro_type"]["Filtro_ip"]["Filtro_type"]["doc_count"])
                
            P7=[]#PTR por hora
            for item in ips:
                query=consultas.sentencia_p7(item,gte,lte)
                r = requests.get(uri,headers=HEADERS, data=query).json()
                P7.append(r["aggregations"]["Filtro_type"]["Filtro_ip"]["Filtro_type"]["doc_count"])
            
            P8=[]#num servidores distintos consultados por hora
            for item in ips:
                query=consultas.sentencia_p8(item,gte,lte)
                r = requests.get(uri,headers=HEADERS, data=query).json()
                P8.append(r["aggregations"]["Filtro_type"]["Filtro_ip"]["unique_ids"]["value"])
            
            P9=[] #TLD consultados por hora
            for item in ips:
                query=consultas.sentencia_p9(item,gte,lte)
                r = requests.get(uri,headers=HEADERS, data=query).json()
                P9.append(r["aggregations"]["Filtro_type"]["Filtro_ip"]["unique_ids"]["value"])
                    
            P10=[]#SLD consultados por hora
            for item in ips:
              query=consultas.sentencia_p10(item,gte,lte)
              r = requests.get(uri,headers=HEADERS, data=query).json()
              P10.append(r["aggregations"]["Filtro_type"]["Filtro_ip"]["unique_ids"]["value"])
                      
            #relacion de unicidad por hora    
            P11=[round(ai/bi,4) if bi!=0 else 0 for ai,bi in zip(P1,P2)]
            
            P12=[]#NXDOMAIN por hora
            for item in ips:
                query=consultas.sentencia_p12(item,gte,lte)
                r = requests.get(uri,headers=HEADERS, data=query).json()
                P12.append(r["aggregations"]["Filtro_type"]["Filtro_ip"]["Filtro_type"]["doc_count"])
            
            P13=[]#num ciudades distintas por hora
            for item in ips:
                query=consultas.sentencia_p13(item,gte,lte)
                r = requests.get(uri,headers=HEADERS, data=query).json()
                P13.append(r["aggregations"]["Filtro_type"]["Filtro_ip"]["unique_ids"]["value"])
                
            P14=[]#num paises distintos por hora
            for item in ips:
                query=consultas.sentencia_p14(item,gte,lte)
                r = requests.get(uri,headers=HEADERS, data=query).json()
                P14.append(r["aggregations"]["Filtro_type"]["Filtro_ip"]["unique_ids"]["value"])
                
            P15=[]#relacion de flujo por hora
            for item in ips:
                query=consultas.sentencia_p15(item,gte,lte)
                r = requests.get(uri,headers=HEADERS, data=query).json()
                P15.append(r["aggregations"]["Filtro_type"]["Filtro_ip"]["Filtro_type"]["doc_count"])
            P15=[round(ai/bi,4) if bi!=0 else 0 for ai,bi in zip(P2,P15)]
            #print(P1_1,ips,P1,P2,P3,P4,P5,P6,P7,P8,P9,P10,P11,P12,P15)
            
#            datos_finales=[["@timestamp",time,
#                            "ip",ip,"p1",p1,"p2",p2,"p3",p3,"p4",p4,"p5",p5,
#                            "p6",p6,"p7",p7,"p8",p8,"p9",p9,"p10",p10,"p11",
#                            p11,"p12",p12,"p13",p13,"p14",p14,"p15",p15] 
#                            for time,ip,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15 
#                            in zip(P1_1,ips,P1,P2,P3,P4,P5,P6,P7,P8,P9,P10,P11,P12,P13,P14,P15)]
#                        
#            datos_finales_json=[Convert(item) for item in datos_finales]
#    
#            for item in datos_finales_json:
#                res=es.index(index='fingerprints',doc_type='fingerprints',id=ii,body=item)
#                ii=ii+1
                
            index_array=[j for j in range(indexs,indexs+len(P1))]
            indexs=indexs+len(P1)
                 
            data={"index":index_array,"@timestamp":P1_1,"ip":ips,'P1':P1,'P2':P2,'P3':P3,'P4':P4,'P5':P5,
                  'P6':P6,'P7':P7,'P8':P8,'P9':P9,'P10':P10,
                  'P11':P11,'P12':P12,'P13':P13,'P14':P14,'P15':P15}
            
            df=pd.DataFrame(data,columns=['index','@timestamp','ip','P1','P2','P3','P4','P5',
                                          'P6','P7','P8','P9','P10',
                                          'P11','P12','P13','P14','P15'])
            path =  'fingerprints.csv'
            df.to_csv(path, index=None, mode="a", header=not os.path.isfile(path))
            
    matriz_num_host.append(numero_hosts)
            
M_N_H=np.array(matriz_num_host)
M_N_H=M_N_H.transpose()
np.savetxt("num_host.csv",M_N_H,fmt="%d",delimiter=",")