import unittest
import json
from session_analyzer import SessionAnalyzer

session = '{"uuid": "c546114f97f548f982756495f963e280", "start_time": 1466091813.4780173, ' \
          '"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2767.4 Safari/537.36", ' \
          '"end_time": 1466091899.9854035, "sensor": "78e51180-bf0d-4757-8a04-f000e5efa179", "count": 24, ' \
          '"paths": [{"timestamp": 1466091813.4779778, "path": "/", "attack_type": "index", "response_status": 200}, ' \
          '{"timestamp": 1466091842.7088752, "path": "/fluent-python.html", "attack_type": "index", "response_status": 200}, ' \
          '{"timestamp": 1466091858.214475, "path": "/wow-movie.html?exec=/bin/bash", "attack_type": "index", "response_status": 200}, ' \
          '{"timestamp": 1466091871.9076045, "path": "/wow-movie.html?exec=/etc/passwd", "attack_type": "lfi", "response_status": 200}, ' \
          '{"timestamp": 1466091885.1003792, "path": "/wow-movie.html?exec=/bin/bash", "attack_type": "index", "response_status": 200}, ' \
          '{"timestamp": 1466091899.9854052, "path": "/wow-movie.html?exec=/../../../..///././././.../../../etc/passwd", "attack_type": "lfi", "response_status": 200}], ' \
          '"peer": {"port": 56970, "ip": "192.168.1.3"}}'


class TestSessionAnalyzer(unittest.TestCase):
    def setUp(self):
        self.session = json.loads(session)
        self.handler = SessionAnalyzer()

    def test_create_stats(self):
        stats = self.handler.create_stats(self.session)
        self.assertEqual(stats['possible_owners'], ['attacker'])
