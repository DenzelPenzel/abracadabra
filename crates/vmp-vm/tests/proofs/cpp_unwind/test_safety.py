"""Regression gates for proof preconditions, using real replay and child interpreters."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

import pefile
import snapshot

ROOT = Path(__file__).resolve().parent


class SafetyTests(unittest.TestCase):
    def test_optimized_entrypoints_refuse_before_execution(self):
        for script in ('snapshot.py', 'windows.py'):
            for flags, optimization in ((['-O'], ''), (['-OO'], ''), ([], '1')):
                with self.subTest(script=script, flags=flags, optimization=optimization):
                    env = dict(os.environ, PYTHONOPTIMIZE=optimization)
                    result = subprocess.run([sys.executable, *flags, str(ROOT / script)],
                                            env=env, capture_output=True, text=True, timeout=60)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('optimized Python is unsupported', result.stderr)
                    self.assertNotIn('PASS:', result.stdout)

    def test_live_image_changes_are_rejected(self):
        self.assertTrue(hasattr(snapshot, 'verified_image'), 'live image validation is missing')
        for variant, lhs, rhs, checkpoint, data, uc in snapshot.snapshots():
            pe = pefile.PE(data=data)
            base, size = pe.OPTIONAL_HEADER.ImageBase, pe.OPTIONAL_HEADER.SizeOfImage
            image = snapshot.verified_image(pe, uc)
            self.assertEqual(len(image), size)
            for offset in (0, size - 1):
                original = bytes(uc.mem_read(base + offset, 1))
                uc.mem_write(base + offset, bytes([original[0] ^ 1]))
                with self.assertRaisesRegex(AssertionError, 'live image changed'):
                    snapshot.verified_image(pe, uc)
                uc.mem_write(base + offset, original)
                self.assertEqual(snapshot.verified_image(pe, uc), image)


if __name__ == '__main__':
    unittest.main()
