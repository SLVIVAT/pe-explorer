import unittest

from pe.constants import machine_name, section_characteristic_names


class PEConstantsTests(unittest.TestCase):
    def test_section_alignment_is_decoded_as_one_exclusive_value(self) -> None:
        names = section_characteristic_names(0x00300000)

        self.assertEqual(names, ("4-byte alignment",))

    def test_recognizes_current_arm64_machine_types(self) -> None:
        self.assertEqual(machine_name(0xA641), "ARM64EC")
        self.assertEqual(machine_name(0xA64E), "ARM64X")


if __name__ == "__main__":
    unittest.main()
