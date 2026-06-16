import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
import time
from data_processing.live_capture import LiveCaptureService

class TestLiveCapture(unittest.TestCase):
    @patch('data_processing.live_capture.EvidenceIngestor')
    def setUp(self, MockIngestor):
        self.mock_ingestor = MockIngestor.return_value
        self.service = LiveCaptureService(
            interface="lo0",
            case_id="test-case-uuid",
            interval=1,
            user_id="test-user-uuid"
        )

    @patch('data_processing.live_capture.wrpcap')
    def test_packet_aggregation_and_flush(self, mock_wrpcap):
        # Mocking ingestor.ingest
        self.mock_ingestor.ingest.return_value = "evidence-uuid"
        
        # Simulate receiving packets
        mock_packet = MagicMock()
        self.service.packet_handler(mock_packet)
        self.service.packet_handler(mock_packet)
        
        self.assertEqual(len(self.service.packet_buffer), 2)
        
        # Wait for interval to pass
        time.sleep(1.1)
        
        # Next packet should trigger flush
        self.service.packet_handler(mock_packet)
        
        # Verify wrpcap was called
        mock_wrpcap.assert_called_once()
        
        # Verify ingestor was called
        self.mock_ingestor.ingest.assert_called_once()
        
        # Verify buffer was cleared
        self.assertEqual(len(self.service.packet_buffer), 0)

    @patch('data_processing.live_capture.sniff')
    def test_start_and_stop(self, mock_sniff):
        # Simulate a small number of packets
        self.service.start(count=5)
        
        # Verify sniff was called with correct arguments
        mock_sniff.assert_called_once()
        args, kwargs = mock_sniff.call_args
        self.assertEqual(kwargs['iface'], "lo0")
        self.assertEqual(kwargs['count'], 5)

if __name__ == "__main__":
    unittest.main()
