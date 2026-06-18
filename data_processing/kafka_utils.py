import json
import os
from typing import Any, Dict, Optional

# Pure-python wrappers using kafka-python-ng to mimic confluent-kafka API contracts

class MessageWrapper:
    def __init__(self, record):
        self._record = record
        
    def error(self):
        return None
        
    def topic(self) -> str:
        return self._record.topic
        
    def value(self) -> bytes:
        return self._record.value


class KafkaConsumerWrapper:
    def __init__(self, bootstrap_servers: str, group_id: str, auto_offset_reset: str):
        from kafka import KafkaConsumer
        self.consumer = KafkaConsumer(
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
            auto_offset_reset=auto_offset_reset,
            enable_auto_commit=True
        )
        self.records_queue = []
        
    def subscribe(self, topics):
        self.consumer.subscribe(topics)
        
    def poll(self, timeout: float):
        if self.records_queue:
            return MessageWrapper(self.records_queue.pop(0))
            
        timeout_ms = int(timeout * 1000)
        res = self.consumer.poll(timeout_ms=timeout_ms)
        if not res:
            return None
            
        for tp, records in res.items():
            self.records_queue.extend(records)
            
        if self.records_queue:
            return MessageWrapper(self.records_queue.pop(0))
            
        return None


class KafkaProducerWrapper:
    def __init__(self, bootstrap_servers: str):
        from kafka import KafkaProducer
        self.producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers
        )
        
    def produce(self, topic: str, key: str, value: Any, callback=None):
        key_bytes = key.encode('utf-8') if isinstance(key, str) else key
        value_bytes = value.encode('utf-8') if isinstance(value, str) else value
        future = self.producer.send(topic, key=key_bytes, value=value_bytes)
        
        if callback:
            class MockMsg:
                def topic(self): return topic
                def partition(self): return 0
                
            def on_success(record_metadata):
                callback(None, MockMsg())
            def on_error(excp):
                callback(excp, MockMsg())
                
            future.add_callback(on_success)
            future.add_errback(on_error)
            
    def flush(self):
        self.producer.flush()


def get_kafka_producer() -> KafkaProducerWrapper:
    bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", os.getenv("KAFKA_PORT", "localhost:9092"))
    if ":" not in bootstrap_servers and bootstrap_servers.isdigit():
        bootstrap_servers = f"localhost:{bootstrap_servers}"
    return KafkaProducerWrapper(bootstrap_servers)


def get_kafka_consumer(group_id: str) -> KafkaConsumerWrapper:
    bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", os.getenv("KAFKA_PORT", "localhost:9092"))
    if ":" not in bootstrap_servers and bootstrap_servers.isdigit():
        bootstrap_servers = f"localhost:{bootstrap_servers}"
    return KafkaConsumerWrapper(
        bootstrap_servers=bootstrap_servers,
        group_id=group_id,
        auto_offset_reset="earliest",
    )


def delivery_report(err, msg):
    if err is not None:
        print(f"Message delivery failed: {err}")
    else:
        print(f"Message delivered to {msg.topic()} [{msg.partition()}]")


def produce_message(producer: KafkaProducerWrapper, topic: str, key: str, value: Dict[str, Any]):
    producer.produce(
        topic,
        key=key,
        value=json.dumps(value),
        callback=delivery_report,
    )
    producer.flush()
