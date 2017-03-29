import asyncio
import unittest
from tanner.emulators import base
from unittest import mock

class TestBase(unittest.TestCase):
	def setUp(self):
		self.session = mock.Mock()
		self.session.associate_db = mock.Mock()
		self.data = mock.Mock()
		with mock.patch('tanner.emulators.lfi.LfiEmulator', mock.Mock(), create=True):
			self.handler = base.BaseHandler('/tmp/', 'test.db')

	def test_handle_get_sqli(self):
		path = '/index.html?id=1 UNION SELECT 1'

		@asyncio.coroutine
		def mock_sqli_check_get_data(path):
			return 1;

		@asyncio.coroutine
		def mock_sqli_handle(path, session, post_request=0):
			return 'sqli_test_payload'

		self.handler.emulators['sqli'] = mock.Mock()
		self.handler.emulators['sqli'].check_get_data = mock_sqli_check_get_data
		self.handler.emulators['sqli'].handle = mock_sqli_handle

		loop = asyncio.get_event_loop()
		detection = loop.run_until_complete(self.handler.handle_get(self.session, path))

		assert_detection = {'name': 'sqli', 'order': 2, 'payload': 'sqli_test_payload'}
		self.assertDictEqual(detection, assert_detection)

	def test_handle_post_sqli(self):

		@asyncio.coroutine
		def mock_xss_handle(value, session, raw_data=None):
			return None

		self.handler.emulators['xss'] = mock.Mock()
		self.handler.emulators['xss'].handle = mock_xss_handle	

		@asyncio.coroutine
		def mock_sqli_check_post_data(data):
			return 1;

		@asyncio.coroutine
		def mock_sqli_handle(path, session, post_request=0):
			return 'sqli_test_payload'

		self.handler.emulators['sqli'] = mock.Mock()
		self.handler.emulators['sqli'].check_post_data = mock_sqli_check_post_data
		self.handler.emulators['sqli'].handle = mock_sqli_handle

		loop = asyncio.get_event_loop()
		detection = loop.run_until_complete(self.handler.handle_post(self.session, self.data))

		assert_detection = {'name': 'sqli', 'order': 2, 'payload': 'sqli_test_payload'}
		self.assertDictEqual(detection, assert_detection)
