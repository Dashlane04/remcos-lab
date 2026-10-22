import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('addresses', Path(__file__).parents[1] / 'scripts/configure_addresses.py')
addresses = importlib.util.module_from_spec(spec)
spec.loader.exec_module(addresses)


class AddressSettingsTests(unittest.TestCase):
    def test_only_addresses_change_and_backup_is_exact(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'infra').mkdir()
            original = b'# test\r\nLAB_SERVER_IP=192.168.56.10\r\nDATA_BIND_IP=127.0.0.1\r\nPASSWORD="literal$stuff"\r\n'
            settings = root / 'infra/.env'
            settings.write_bytes(original)
            self.assertTrue(addresses.update_addresses(root, '10.10.10.1', '172.19.102.172'))
            expected = original.replace(b'192.168.56.10', b'10.10.10.1').replace(b'127.0.0.1', b'172.19.102.172')
            self.assertEqual(settings.read_bytes(), expected)
            self.assertEqual(next((root / 'data/raw/maintenance-backups').glob('*.env')).read_bytes(), original)
            self.assertFalse(addresses.update_addresses(root, '10.10.10.1', '172.19.102.172'))
            self.assertEqual(len(list((root / 'data/raw/maintenance-backups').glob('*.env'))), 1)

    def test_bad_address_or_duplicate_key_never_mutates_settings(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'infra').mkdir()
            settings = root / 'infra/.env'
            original = b'LAB_SERVER_IP=10.10.10.1\nLAB_SERVER_IP=10.10.10.2\nDATA_BIND_IP=127.0.0.1\n'
            settings.write_bytes(original)
            for server, bind in [('8.8.8.8', '172.19.1.1'), ('10.10.10.1', '127.0.0.1'), ('10.10.10.1', '172.19.1.1')]:
                with self.assertRaises(ValueError):
                    addresses.update_addresses(root, server, bind)
                self.assertEqual(settings.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
