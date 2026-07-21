from __future__ import annotations

from dataclasses import FrozenInstanceError
import unittest

from pe.addressing import AddressingService
from pe.search import SearchQueryError, SearchService
from tests.test_addressing import _optional_header, _section


def _service(*, pe32_plus: bool = False) -> SearchService:
    data = bytearray(0x800)
    data[0x220:0x225] = b"Hello"
    data[0x250:0x25A] = "World".encode("utf-16le")
    data[0x280:0x284] = b"\xDE\xAD\xBE\xEF"
    data[0x700:0x704] = b"\xDE\xAD\xBE\xEF"
    mapper = AddressingService(
        _optional_header(pe32_plus=pe32_plus),
        (_section(raw_size=0x200, virtual_size=0x300),),
        file_size=len(data),
    )
    return SearchService(bytes(data), mapper, preview_bytes=4)


class SearchServiceTests(unittest.TestCase):
    def test_ascii_search_returns_all_gui_address_fields(self) -> None:
        result = _service().search("Hello", "ascii")[0]

        self.assertEqual(result.offset, 0x220)
        self.assertEqual(result.rva, 0x1020)
        self.assertEqual(result.va, 0x401020)
        self.assertEqual(result.section, ".text")
        self.assertEqual(result.length, 5)
        self.assertIn("Hello", result.preview)
        self.assertEqual(result.mode, "ascii")
        self.assertEqual(result.to_dict()["offset"], 0x220)
        with self.assertRaises(FrozenInstanceError):
            result.offset = 0  # type: ignore[misc]

    def test_utf16le_search_supports_unicode_and_pe32_plus_addresses(self) -> None:
        result = _service(pe32_plus=True).search("World", "utf-16le")[0]

        self.assertEqual(result.offset, 0x250)
        self.assertEqual(result.rva, 0x1050)
        self.assertEqual(result.va, 0x140001050)
        self.assertEqual(result.length, 10)

    def test_hex_search_accepts_common_separators_and_finds_overlay(self) -> None:
        service = _service()
        spaced = service.search("0xDE 0xAD:BE-EF", "hex")
        compact = service.search("DEADBEEF", "hex")

        self.assertEqual(
            tuple(result.offset for result in spaced),
            (0x280, 0x700),
        )
        self.assertEqual(spaced, compact)
        self.assertEqual(spaced[0].rva, 0x1080)
        self.assertIsNone(spaced[1].rva)
        self.assertIsNone(spaced[1].va)
        self.assertIsNone(spaced[1].section)

    def test_exact_rva_va_and_file_offset_queries(self) -> None:
        service = _service()
        by_rva = service.search("1020", "rva")[0]
        by_va = service.search("0x401020", "va")[0]
        by_offset = service.search("220", "file-offset")[0]

        for result in (by_rva, by_va, by_offset):
            self.assertEqual(result.offset, 0x220)
            self.assertEqual(result.rva, 0x1020)
            self.assertEqual(result.va, 0x401020)
            self.assertEqual(result.section, ".text")

        decimal_offset = service.search("0d544", "file-offset")[0]
        self.assertEqual(decimal_offset.offset, 0x220)

    def test_exact_virtual_and_overlay_addresses_remain_inspectable(self) -> None:
        service = _service()

        virtual = service.search("1250", "rva")[0]
        overlay = service.search("700", "file-offset")[0]

        self.assertIsNone(virtual.offset)
        self.assertEqual(virtual.rva, 0x1250)
        self.assertEqual(virtual.va, 0x401250)
        self.assertEqual(virtual.section, ".text")
        self.assertIn("No file-backed", virtual.preview)
        self.assertEqual(overlay.offset, 0x700)
        self.assertIsNone(overlay.rva)

    def test_overlapping_matches_and_result_limit_are_deterministic(self) -> None:
        data = b"AAAA"
        mapper = AddressingService(
            _optional_header(size_of_image=0x1000, size_of_headers=4),
            (),
            file_size=4,
        )
        service = SearchService(data, mapper)

        results = service.search("AA", "ascii", max_results=2)

        self.assertEqual(tuple(result.offset for result in results), (0, 1))

    def test_rejects_malformed_text_and_hex_queries(self) -> None:
        service = _service()
        cases = (
            ("", "ascii"),
            ("café", "ascii"),
            ("", "utf-16le"),
            ("", "hex"),
            ("ABC", "hex"),
            ("GG", "hex"),
            ("DE ?? AD", "hex"),
        )
        for query, mode in cases:
            with self.subTest(query=query, mode=mode):
                with self.assertRaises(SearchQueryError):
                    service.search(query, mode)

    def test_rejects_malformed_or_out_of_range_address_queries(self) -> None:
        service = _service()
        cases = (
            ("", "rva"),
            ("-1", "rva"),
            ("not-an-address", "rva"),
            ("500", "rva"),
            ("3FFFFF", "va"),
            ("800", "file-offset"),
        )
        for query, mode in cases:
            with self.subTest(query=query, mode=mode):
                with self.assertRaises(SearchQueryError):
                    service.search(query, mode)

    def test_rejects_invalid_modes_limits_and_preview_sizes(self) -> None:
        service = _service()
        with self.assertRaisesRegex(SearchQueryError, "Unsupported"):
            service.search("Hello", "regex")
        for limit in (0, -1):
            with self.subTest(limit=limit):
                with self.assertRaisesRegex(ValueError, "positive"):
                    service.search("Hello", "ascii", max_results=limit)
        with self.assertRaises(TypeError):
            service.search("Hello", "ascii", max_results=True)
        mapper = AddressingService(
            _optional_header(),
            (_section(),),
            file_size=0,
        )
        with self.assertRaises(ValueError):
            SearchService(b"", mapper, preview_bytes=-1)


if __name__ == "__main__":
    unittest.main()
