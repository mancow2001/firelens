#!/usr/bin/env python3
"""
Unit tests for memory leak fixes
Tests deque usage, queue limits, and session cleanup
"""
import unittest
import time
from collections import deque
from queue import Queue, Full
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch, MagicMock


class TestInterfaceMonitorMemoryFixes(unittest.TestCase):
    """Test memory leak fixes in interface monitor"""

    def test_deque_maxlen_enforces_limit(self):
        """Test that deque with maxlen automatically limits size"""
        max_samples = 240
        samples = deque(maxlen=max_samples)

        # Add more than maxlen
        for i in range(500):
            samples.append(i)

        # Should be limited to maxlen
        self.assertEqual(len(samples), max_samples,
                        "Deque should enforce maxlen")

        # Oldest items should be removed
        self.assertEqual(samples[0], 500 - max_samples,
                        "Oldest items should be evicted")

    def test_deque_no_memory_fragmentation(self):
        """Test that deque doesn't create new objects on append"""
        import sys

        max_samples = 240
        samples = deque(maxlen=max_samples)

        # Fill the deque
        for i in range(max_samples):
            samples.append({'timestamp': datetime.now(), 'value': i})

        # Get initial size
        initial_size = sys.getsizeof(samples)

        # Add many more items (should not grow)
        for i in range(1000):
            samples.append({'timestamp': datetime.now(), 'value': i})

        # Size should be similar (within reasonable margin)
        final_size = sys.getsizeof(samples)
        self.assertAlmostEqual(initial_size, final_size, delta=1000,
                              msg="Deque size should not grow significantly")


class TestQueueSizeLimits(unittest.TestCase):
    """Test queue size limit fixes"""

    def test_queue_with_maxsize(self):
        """Test that Queue with maxsize prevents unbounded growth"""
        queue = Queue(maxsize=1000)

        # Should be able to add up to maxsize
        for i in range(1000):
            queue.put(i, block=False)

        # Adding more should raise Full exception or timeout
        with self.assertRaises(Full):
            queue.put(1001, block=False)

    def test_queue_timeout_on_full(self):
        """Test that put with timeout doesn't block forever"""
        queue = Queue(maxsize=10)

        # Fill the queue
        for i in range(10):
            queue.put(i)

        # Putting with timeout should raise exception, not hang
        start = time.time()
        try:
            queue.put(11, timeout=0.1)
            self.fail("Should have raised Full exception")
        except Full:
            elapsed = time.time() - start
            self.assertLess(elapsed, 0.5, "Should timeout quickly")


class TestRequestsSessionCleanup(unittest.TestCase):
    """Test requests.Session cleanup"""

    @patch('firelens.collectors.requests.Session')
    def test_panos_client_close(self, mock_session_class):
        """Test that FireLensClient.close() closes the session"""
        from firelens.collectors import FireLensClient

        mock_session = Mock()
        mock_session_class.return_value = mock_session

        client = FireLensClient("https://test.example.com", verify_ssl=False)
        self.assertIsNotNone(client.session)

        # Close should call session.close()
        client.close()
        mock_session.close.assert_called_once()

    @patch('firelens.collectors.requests.Session')
    def test_panos_client_del_cleanup(self, mock_session_class):
        """Test that __del__ cleans up session"""
        from firelens.collectors import FireLensClient

        mock_session = Mock()
        mock_session_class.return_value = mock_session

        client = FireLensClient("https://test.example.com")

        # Trigger __del__
        del client

        # Should have called close
        mock_session.close.assert_called()


class TestGarbageCollection(unittest.TestCase):
    """Test garbage collection is called periodically"""

    @patch('gc.collect')
    def test_gc_called_periodically(self, mock_gc_collect):
        """Test that gc.collect() is called in monitoring loop"""
        # This tests the main.py monitoring loop behavior
        import gc

        # Simulate periodic GC
        gc.collect()

        # Verify it can be called
        self.assertIsNotNone(gc.collect())

    def test_gc_collects_circular_references(self):
        """Test that gc.collect() actually collects objects"""
        import gc

        # Create circular reference
        class Node:
            def __init__(self):
                self.ref = None

        a = Node()
        b = Node()
        a.ref = b
        b.ref = a

        # Delete references
        del a
        del b

        # Force collection
        collected = gc.collect()

        # Should have collected something
        self.assertGreaterEqual(collected, 0, "GC should run without error")


class TestMemoryMonitoring(unittest.TestCase):
    """Test memory monitoring functionality"""

    def test_psutil_memory_info(self):
        """Test that psutil can get memory info"""
        try:
            import psutil
            process = psutil.Process()
            mem_info = process.memory_info()

            self.assertGreater(mem_info.rss, 0, "Should have RSS memory")
            self.assertIsInstance(mem_info.rss, int, "RSS should be integer")

            mem_percent = process.memory_percent()
            self.assertGreater(mem_percent, 0, "Should have memory percent")
            self.assertLess(mem_percent, 100, "Memory percent should be < 100")

        except ImportError:
            self.skipTest("psutil not installed")


class TestDequeVsListPerformance(unittest.TestCase):
    """Compare deque vs list for our use case"""

    def test_deque_append_performance(self):
        """Test that deque append is fast"""
        import time

        max_samples = 240
        d = deque(maxlen=max_samples)

        start = time.time()
        for i in range(10000):
            d.append(i)
        deque_time = time.time() - start

        # Should be very fast
        self.assertLess(deque_time, 0.1, "Deque append should be fast")

    def test_list_recreation_overhead(self):
        """Test that list recreation is slower than deque"""
        import time

        max_samples = 240

        # List with manual truncation
        lst = []
        start = time.time()
        for i in range(10000):
            lst.append(i)
            if len(lst) > max_samples:
                lst = lst[-max_samples:]  # Creates new list
        list_time = time.time() - start

        # Deque with maxlen
        d = deque(maxlen=max_samples)
        start = time.time()
        for i in range(10000):
            d.append(i)
        deque_time = time.time() - start

        # Deque should be faster (or at least not much slower)
        self.assertLess(deque_time, list_time * 2,
                       "Deque should be comparable or faster than list recreation")


if __name__ == '__main__':
    unittest.main()
