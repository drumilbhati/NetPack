from typing import List, Dict, Any
from fastapi import APIRouter
import random

router = APIRouter()

@router.get("/")
async def get_graph_data():
    """
    Returns mock flow data for graph visualization.
    In a real app, this would query ES or Postgres and aggregate flows.
    """
    ips = [
        "192.168.1.1", "192.168.1.50", "192.168.1.100", 
        "10.0.0.5", "10.0.0.10", "172.16.0.1",
        "8.8.8.8", "1.1.1.1"
    ]
    
    nodes = []
    for ip in ips:
        is_anomaly = random.random() > 0.8
        nodes.append({
            "id": ip,
            "label": ip,
            "color": "red" if is_anomaly else "#2563eb"
        })
        
    links = [
        {"source": "192.168.1.1", "target": "192.168.1.50"},
        {"source": "192.168.1.1", "target": "192.168.1.100"},
        {"source": "192.168.1.50", "target": "10.0.0.5"},
        {"source": "192.168.1.100", "target": "10.0.0.10"},
        {"source": "10.0.0.5", "target": "172.16.0.1"},
        {"source": "172.16.0.1", "target": "8.8.8.8"},
        {"source": "172.16.0.1", "target": "1.1.1.1"},
        {"source": "192.168.1.1", "target": "8.8.8.8"},
    ]
    
    return {"nodes": nodes, "links": links}
