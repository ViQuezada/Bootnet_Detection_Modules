#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Nov 16 17:13:27 2020

@author: vicente

la estructura de las diferentes consultas realizadas a elasticsearch
los parametros cambias dependiendo lo que se desee consultar
"""
import json

# numero de hosts
def sentencia_p1_1(gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {"num_hosts": {"cardinality": {"field": "src_ip.keyword"}}},
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# numero de solicitudes dns por hora
def sentencia_p1(size, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "sacar_ip": {
                            "terms": {
                                "field": "src_ip.keyword",
                                "min_doc_count":100,
                                "order": {"_count": "desc"},
                                "size": size,
                            }
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# numero de solicitudes dns por hora
def sentencia_p2(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "Filtro_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "unique_ids": {
                                    "cardinality": {"field": "dns.rrname.keyword"}
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# la mayor cantidad de solititudes para un solo dominio por hora
def sentencia_p3(item, size, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "Filtro_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "dnss": {
                                    "terms": {
                                        "field": "dns.rrname.keyword",
                                        "order": {"_count": "desc"},
                                        "size": 1,
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# Numero medio de solicitudes por minuto
# se saca la solicitudes por minuto
def sentencia_p4(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "Filtro_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "tiempos": {
                                    "date_histogram": {
                                        "field": "@timestamp",
                                        "fixed_interval": "1m",
                                        "time_zone": "America/Guayaquil",
                                        "min_doc_count": 1,
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# num de consultas de registros Mx por hora
def sentencia_p6(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "Filtro_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "Filtro_type": {
                                    "filter": {"term": {"dns.rrtype.keyword": "MX"}}
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# Numero de consutlas PTR por hora
def sentencia_p7(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "Filtro_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "Filtro_type": {
                                    "filter": {"term": {"dns.rrtype.keyword": "PTR"}}
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# numero de servidores dns distintos consultados por hora
def sentencia_p8(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "Filtro_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "unique_ids": {
                                    "cardinality": {"field": "dest_ip.keyword"}
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# sacar el numero de tld para cada host
def sentencia_p9(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "Filtro_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "unique_ids": {
                                    "cardinality": {"field": "dn.tld.keyword"}
                                }
                            }
                        }
                    }
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query

# sacar el numero de tld para cada host
def sentencia_p10(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "Filtro_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "unique_ids": {
                                    "cardinality": {"field": "dn.sld.keyword"}
                                }
                            }
                        }
                    }
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query

# NXDOMAIN por hora
def sentencia_p12(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "answer"}},
                    "aggs": {
                        "Filtro_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "Filtro_type": {
                                    "filter": {
                                        "term": {"dns.rcode.keyword": "NXDOMAIN"}
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# de ciudades disintas
def sentencia_p13(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "answer"}},
                    "aggs": {
                        "Filtro_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "unique_ids": {
                                    "cardinality": {"field": "geoip.city_name.keyword"}
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# de paisesdistintos
def sentencia_p14(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "answer"}},
                    "aggs": {
                        "Filtro_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "unique_ids": {
                                    "cardinality": {
                                        "field": "geoip.country_name.keyword"
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# Relacion de flujo por hora
def sentencia_p15(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "answer"}},
                    "aggs": {
                        "Filtro_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "Filtro_type": {
                                    "filter": {"term": {"dns.rcode.keyword": "NOERROR"}}
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query

def sentencia_pNX0(item, gte, lte):
    query = json.dumps(
        {
          "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "Filtro_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "unique_ids": {
                                    "cardinality": {"field": "dn.sld.keyword"}
                                }
                            }
                        }
                    }
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


def sentencia_pNX(item, size, gte, lte):
    query = json.dumps(
        {
          "aggs": {
                "Filtro_type": {
                    "filter": {"term": {"dns.type.keyword": "answer"}},
                    "aggs": {
                        "Filtro_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "Filtro_NX": {
                                  "filter":{"term": {
                                    "dns.rcode.keyword": "NXDOMAIN"
                                  }},
                                  "aggs":{
                                    "Filtro_dls":{
                                      "terms":{
                                        "field": "dn.sld.keyword",
                                        "size": size
                                      }
                                      
                                    }
                                  }
                                }
                            }
                        }
                    }
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query
