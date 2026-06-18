import unittest
from unittest.mock import MagicMock, patch
import base64

from data_processing.live_capture import LiveCaptureService

class DummyPacket:
    def __init__(self, raw_bytes, timestamp):
        self.raw_bytes = raw_bytes
        self.time = timestamp

    def __bytes__(self):
        return self.raw_bytes

class TestLiveCapture(unittest.TestCase):
    @patch('data_processing.live_capture.get_kafka_producer')
    def setUp(self, mock_get_producer):
        self.mock_producer = mock_get_producer.return_value
        self.service = LiveCaptureService(
            interface="lo0",
            case_id="test-case-uuid",
            batch_size=3,
            user_id="test-user-uuid"
        )

    @patch('data_processing.live_capture.produce_message')
    def test_packet_aggregation_and_flush(self, mock_produce_message):
        # Create dummy packets
        packet = DummyPacket(b"raw_packet_bytes", 1625000000.0)

        # 1. Feed first packet
        self.service.packet_handler(packet)
        self.assertEqual(len(self.service.packet_buffer), 1)
        mock_produce_message.assert_not_called()

        # 2. Feed second packet
        self.service.packet_handler(packet)
        self.assertEqual(len(self.service.packet_buffer), 2)
        mock_produce_message.assert_not_called()

        # 3. Feed third packet (triggers batch_size limit and flushes to Kafka)
        self.service.packet_handler(packet)
        self.assertEqual(len(self.service.packet_buffer), 0)
        mock_produce_message.assert_called_once()

        # Verify produce_message parameters
        args, kwargs = mock_produce_message.call_args
        # args[0] is producer
        self.assertEqual(args[1], "raw-capture-chunks")
        self.assertEqual(args[2], "test-case-uuid")
        
        payload = args[3]
        self.assertEqual(payload["case_id"], "test-case-uuid")
        self.assertEqual(payload["user_id"], "test-user-uuid")
        self.assertEqual(len(payload["packets"]), 3)
        self.assertEqual(payload["packets"][0]["data"], base64.b64encode(b"raw_packet_bytes").decode("utf-8"))

    @patch('data_processing.live_capture.sniff')
    def test_start_and_stop(self, mock_sniff):
        # Simulate starting sniff
        self.service.start(count=5)
        
        # Verify sniff was called with correct arguments
        mock_sniff.assert_called_once()
        args, kwargs = mock_sniff.call_args
        self.assertEqual(kwargs['iface'], "lo0")
        self.assertEqual(kwargs['count'], 5)

if __name__ == "__main__":
    unittest.main()
