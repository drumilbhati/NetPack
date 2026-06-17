from collections import Counter
from typing import Any, Dict, Tuple

from fastapi import APIRouter, Depends

from app.core.database import get_db_conn
from app.dependencies.auth import get_accessible_case_ids, require_role
from app.schemas.auth import UserContext
from app.schemas.graph import GraphLink, GraphNode, GraphResponse
from app.services.elasticsearch import ElasticsearchService

router = APIRouter()
es_service = ElasticsearchService()


@router.get("/", response_model=GraphResponse)
async def get_graph_data(
    current_user: UserContext = Depends(
        require_role("admin", "investigator", "auditor")
    ),
):
    """
    Build the graph from indexed flow records and case access controls.
    Nodes and links are derived from Elasticsearch sessions, with PostgreSQL
    used to scope the data to cases the user can access.
    """
    conn = None
    try:
        conn = get_db_conn()
        accessible_case_ids = get_accessible_case_ids(conn, current_user)

        sessions = await es_service.get_recent_sessions(
            case_ids=accessible_case_ids,
            size=500,
        )

        if not sessions:
            return GraphResponse(nodes=[], links=[])

        node_stats: Dict[str, Dict[str, Any]] = {}
        link_counts: Counter[Tuple[str, str]] = Counter()

        for session in sessions:
            source_ip = session.get("source_ip")
            destination_ip = session.get("destination_ip")
            if not source_ip or not destination_ip:
                continue

            for ip in (source_ip, destination_ip):
                stats = node_stats.setdefault(
                    ip,
                    {
                        "score": 0,
                        "bytes": 0,
                        "label": ip,
                    },
                )
                stats["bytes"] += int(session.get("bytes_sent") or 0) + int(
                    session.get("bytes_received") or 0
                )
                if session.get("is_anomaly"):
                    stats["score"] += 1

            link_counts[(source_ip, destination_ip)] += 1

        nodes = []
        max_bytes = max((s["bytes"] for s in node_stats.values()), default=1)
        
        for ip, stats in sorted(
            node_stats.items(),
            key=lambda item: (item[1]["score"], item[1]["bytes"]),
            reverse=True,
        ):
            # Calculate relative size (val) between 1 and 20 based on log scale of bytes
            size_val = 1 + (19 * (stats["bytes"] / max_bytes))
            
            nodes.append(
                GraphNode(
                    id=ip,
                    label=stats["label"],
                    color="#dc2626" if stats["score"] > 0 else "#2563eb",
                    val=size_val
                )
            )

        links = [
            GraphLink(source=source, target=target)
            for (source, target), _count in link_counts.most_common(250)
        ]

        return GraphResponse(nodes=nodes, links=links)
    finally:
        if conn is not None:
            conn.close()
