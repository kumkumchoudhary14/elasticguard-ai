"""Application configuration management."""
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    elasticsearch_url: str = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
    elasticsearch_index: str = os.getenv("ELASTICSEARCH_INDEX", "iot-security-events")
    anomaly_index: str = os.getenv("ANOMALY_INDEX", "security-anomalies")
    simulator_interval: float = float(os.getenv("SIMULATOR_INTERVAL", "2"))
    anomaly_check_interval: int = int(os.getenv("ANOMALY_CHECK_INTERVAL", "30"))
    anomaly_probability: float = float(os.getenv("ANOMALY_PROBABILITY", "0.15"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")


settings = Settings()
