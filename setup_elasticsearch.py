"""
Setup Elasticsearch index templates, ILM policies, and ingest pipelines.
Run this before starting the IoT simulator.
"""
import asyncio
import logging
from elasticsearch import AsyncElasticsearch
import os
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ES_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ES_INDEX = os.getenv("ELASTICSEARCH_INDEX", "iot-security-events")
ANOMALY_INDEX = os.getenv("ANOMALY_INDEX", "security-anomalies")


async def create_iot_events_template(es: AsyncElasticsearch) -> None:
    """Create index template for IoT security events."""
    template = {
        "index_patterns": [f"{ES_INDEX}-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "5s"
            },
            "mappings": {
                "properties": {
                    "device_id": {"type": "keyword"},
                    "device_type": {"type": "keyword"},
                    "location": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "@timestamp": {"type": "date"},
                    "severity": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "message": {"type": "text", "analyzer": "standard"},
                    "ip_address": {"type": "ip"},
                    "geo_location": {"type": "geo_point"},
                    "is_anomaly": {"type": "boolean"},
                    "metrics": {
                        "type": "object",
                        "properties": {
                            "cpu_usage": {"type": "float"},
                            "memory_usage": {"type": "float"},
                            "temperature": {"type": "float"},
                            "network_in": {"type": "float"},
                            "network_out": {"type": "float"}
                        }
                    }
                }
            }
        }
    }
    await es.indices.put_index_template(name="iot-security-events-template", body=template)
    logger.info("Created IoT events index template")


async def create_anomalies_template(es: AsyncElasticsearch) -> None:
    """Create index template for security anomalies."""
    template = {
        "index_patterns": [f"{ANOMALY_INDEX}*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "@timestamp": {"type": "date"},
                    "device_id": {"type": "keyword"},
                    "device_type": {"type": "keyword"},
                    "anomaly_type": {"type": "keyword"},
                    "anomaly_score": {"type": "float"},
                    "severity": {"type": "keyword"},
                    "threat_category": {"type": "keyword"},
                    "description": {"type": "text"},
                    "recommended_action": {"type": "text"},
                    "original_event": {"type": "object", "enabled": False},
                    "resolved": {"type": "boolean"}
                }
            }
        }
    }
    await es.indices.put_index_template(name="security-anomalies-template", body=template)
    logger.info("Created anomalies index template")


async def create_ilm_policy(es: AsyncElasticsearch) -> None:
    """Create ILM policy for automatic index rollover."""
    policy = {
        "phases": {
            "hot": {
                "actions": {
                    "rollover": {
                        "max_size": "5gb",
                        "max_age": "1d"
                    }
                }
            },
            "warm": {
                "min_age": "7d",
                "actions": {
                    "shrink": {"number_of_shards": 1},
                    "forcemerge": {"max_num_segments": 1}
                }
            },
            "delete": {
                "min_age": "30d",
                "actions": {"delete": {}}
            }
        }
    }
    await es.ilm.put_lifecycle(name="iot-security-policy", policy=policy)
    logger.info("Created ILM policy")


async def create_ingest_pipeline(es: AsyncElasticsearch) -> None:
    """Create ingest pipeline for event enrichment."""
    pipeline = {
        "description": "Enrich IoT security events",
        "processors": [
            {
                "set": {
                    "field": "@timestamp",
                    "copy_from": "timestamp",
                    "ignore_failure": True
                }
            },
            {
                "set": {
                    "field": "@timestamp",
                    "value": "{{_ingest.timestamp}}",
                    "override": False
                }
            }
        ]
    }
    await es.ingest.put_pipeline(id="iot-security-pipeline", body=pipeline)
    logger.info("Created ingest pipeline")


async def ensure_index_exists(es: AsyncElasticsearch) -> None:
    """Ensure the base index exists."""
    index_name = f"{ES_INDEX}-000001"
    if not await es.indices.exists(index=index_name):
        await es.indices.create(
            index=index_name,
            body={
                "aliases": {ES_INDEX: {"is_write_index": True}}
            }
        )
        logger.info(f"Created index {index_name}")
    else:
        logger.info(f"Index {index_name} already exists")

    if not await es.indices.exists(index=ANOMALY_INDEX):
        await es.indices.create(index=ANOMALY_INDEX)
        logger.info(f"Created anomalies index {ANOMALY_INDEX}")
    else:
        logger.info(f"Anomalies index {ANOMALY_INDEX} already exists")


async def main() -> None:
    """Main setup function."""
    es = AsyncElasticsearch(ES_URL)
    try:
        logger.info(f"Connecting to Elasticsearch at {ES_URL}")
        health = await es.cluster.health()
        logger.info(f"Cluster health: {health['status']}")

        await create_iot_events_template(es)
        await create_anomalies_template(es)
        await create_ilm_policy(es)
        await create_ingest_pipeline(es)
        await ensure_index_exists(es)

        logger.info("Elasticsearch setup complete!")
    except Exception as e:
        logger.error(f"Setup failed: {e}")
        raise
    finally:
        await es.close()


if __name__ == "__main__":
    asyncio.run(main())
