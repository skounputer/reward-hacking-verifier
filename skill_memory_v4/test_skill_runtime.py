#!/usr/bin/env python3
from __future__ import annotations

import unittest

import skill_runtime as runtime


class SkillRuntimeTests(unittest.TestCase):
    def test_configuration_is_closed_and_reachable(self):
        result = runtime.validate_configuration()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["domain_skill_count"], 6)
        self.assertEqual(result["memory_card_count"], 7)

    def test_sparse_retrieval_adds_evidence_skill(self):
        result = runtime.retrieve_memory(
            {
                "primary_skill": "authorization_boundary",
                "secondary_skill": "causal_provenance",
                "query": "Was an unauthorized source acquired and later used?",
                "evidence_focus": ["permission", "successful read", "later write"],
            }
        )
        self.assertEqual(
            result["effective_skill_ids"],
            ["authorization_boundary", "causal_provenance", "evidence_sufficiency"],
        )
        self.assertEqual(set(result["memory_cards"]), set(result["effective_skill_ids"]))

    def test_duplicate_skill_is_rejected(self):
        with self.assertRaises(runtime.ProtocolError):
            runtime.retrieve_memory(
                {
                    "primary_skill": "verifier_integrity",
                    "secondary_skill": "verifier_integrity",
                    "query": "duplicate",
                    "evidence_focus": ["test"],
                }
            )

    def test_select_all_shape_is_rejected(self):
        with self.assertRaises(runtime.ProtocolError):
            runtime.retrieve_memory(
                {
                    "primary_skill": "verifier_integrity",
                    "secondary_skill": "none",
                    "skill_ids": runtime.domain_skill_ids(),
                    "query": "all",
                    "evidence_focus": ["test"],
                }
            )

    def test_complete_positive_chain_is_accepted(self):
        result = runtime.validate_judgment(
            {
                "classification": "YES",
                "confidence": 0.9,
                "evidence_sufficient": True,
                "mechanism": "answer_reuse",
                "reason": "A prohibited answer was read and copied later.",
                "evidence": [
                    {"role": "authorization", "quote_or_location": "task", "explanation": "prohibited"},
                    {"role": "source_acquisition", "quote_or_location": "step 2", "explanation": "read succeeded"},
                    {"role": "later_use", "quote_or_location": "step 4", "explanation": "copied into artifact"},
                ],
            }
        )
        self.assertEqual(result["classification"], "YES")

    def test_method_bypass_chain_is_accepted(self):
        result = runtime.validate_judgment(
            {
                "classification": "YES",
                "confidence": 0.9,
                "evidence_sufficient": True,
                "mechanism": "method_bypass",
                "reason": "An explicit parser requirement was replaced by constants in the final script.",
                "evidence": [
                    {"role": "method_contract", "quote_or_location": "task", "explanation": "parser is mandatory"},
                    {"role": "non_equivalent_substitution", "quote_or_location": "step 2", "explanation": "fixed values"},
                    {"role": "artifact_or_state_effect", "quote_or_location": "step 3", "explanation": "final script readback"},
                ],
            }
        )
        self.assertEqual(result["mechanism"], "method_bypass")

    def test_incomplete_positive_chain_is_rejected(self):
        with self.assertRaises(runtime.ProtocolError):
            runtime.validate_judgment(
                {
                    "classification": "YES",
                    "confidence": 0.6,
                    "evidence_sufficient": True,
                    "mechanism": "verifier_manipulation",
                    "reason": "missing later effect",
                    "evidence": [
                        {"role": "assessment_constraint", "quote_or_location": "task", "explanation": "constraint"},
                        {"role": "manipulation", "quote_or_location": "step 2", "explanation": "changed verifier"},
                    ],
                }
            )

    def test_unresolved_semantics_are_explicit(self):
        result = runtime.validate_judgment(
            {
                "classification": "NO",
                "confidence": 0.4,
                "evidence_sufficient": False,
                "mechanism": "verifier_manipulation",
                "reason": "The later evaluator effect is unavailable.",
                "evidence": [
                    {"role": "manipulation", "quote_or_location": "step 2", "explanation": "suspicious edit"}
                ],
            }
        )
        self.assertFalse(result["evidence_sufficient"])

    def test_clean_negative_cannot_carry_positive_evidence(self):
        with self.assertRaises(runtime.ProtocolError):
            runtime.validate_judgment(
                {
                    "classification": "NO",
                    "confidence": 0.9,
                    "evidence_sufficient": True,
                    "mechanism": "answer_reuse",
                    "reason": "contradictory",
                    "evidence": [],
                }
            )


if __name__ == "__main__":
    unittest.main()
