"""Tests for Issue #177: Privacy hardening batch (federation-specific tests).

Extracted from valence's test_issue_177_hardening.py — only the tests
that exercise federation modules (privacy, consent).
"""

from uuid import uuid4

import pytest

# =============================================================================
# MEDIUM SEVERITY TESTS
# =============================================================================


class TestSensitiveDomainClassification:
    """Test structured classification for sensitive domains."""

    def test_exact_match_works(self):
        """Sensitive domains detected with exact token match."""
        from oro_federation.privacy import is_sensitive_domain

        # Exact matches should work
        assert is_sensitive_domain(["health"]) is True
        assert is_sensitive_domain(["medical"]) is True
        assert is_sensitive_domain(["finance"]) is True
        assert is_sensitive_domain(["legal"]) is True

    def test_path_tokens_detected(self):
        """Domains in paths are detected."""
        from oro_federation.privacy import is_sensitive_domain

        # Path separators should be split
        assert is_sensitive_domain(["personal/health"]) is True
        assert is_sensitive_domain(["data/medical/records"]) is True
        assert is_sensitive_domain(["user_finance"]) is True
        assert is_sensitive_domain(["legal-documents"]) is True

    def test_no_false_positives_from_substring(self):
        """Substring matching no longer causes false positives."""
        from oro_federation.privacy import is_sensitive_domain

        # These should NOT match because we use token matching, not substring
        assert is_sensitive_domain(["weather"]) is False  # contains "the"
        assert is_sensitive_domain(["healthcare_news"]) is True  # health is a token
        assert is_sensitive_domain(["definitely"]) is False  # contains "fin"

    def test_non_sensitive_domains(self):
        """Non-sensitive domains return False."""
        from oro_federation.privacy import is_sensitive_domain

        assert is_sensitive_domain(["science"]) is False
        assert is_sensitive_domain(["sports"]) is False
        assert is_sensitive_domain(["entertainment"]) is False
        assert is_sensitive_domain(["general"]) is False

    def test_get_sensitive_category(self):
        """Category detection works."""
        from oro_federation.privacy import get_sensitive_category

        assert get_sensitive_category("health") == "health"
        assert get_sensitive_category("finance") == "finance"
        assert get_sensitive_category("immigration") == "immigration"
        assert get_sensitive_category("sports") is None


class TestFailedQueryBudgetConsumption:
    """Test that failed k-anonymity queries consume budget."""

    def test_failed_query_consumes_budget(self):
        """Queries failing k-anonymity still consume epsilon."""
        from oro_federation.privacy import (
            FAILED_QUERY_EPSILON_COST,
            PrivacyBudget,
            PrivacyConfig,
            execute_private_query,
        )

        config = PrivacyConfig(min_contributors=5)
        budget = PrivacyBudget(federation_id=uuid4())

        initial_epsilon = budget.spent_epsilon

        # Query with insufficient contributors
        result = execute_private_query(
            confidences=[0.5, 0.6],  # Only 2, need 5
            config=config,
            budget=budget,
            topic_hash="test_topic",
        )

        # Query should fail
        assert result.success is False
        assert "Insufficient contributors" in result.failure_reason

        # But budget should be consumed
        assert result.budget_consumed is True
        assert result.epsilon_consumed == FAILED_QUERY_EPSILON_COST
        assert budget.spent_epsilon == initial_epsilon + FAILED_QUERY_EPSILON_COST

    def test_successful_query_consumes_full_budget(self):
        """Successful queries consume full epsilon."""
        from oro_federation.privacy import (
            PrivacyBudget,
            PrivacyConfig,
            execute_private_query,
        )

        # min_contributors must be >= 5
        config = PrivacyConfig(epsilon=1.0, min_contributors=5)
        budget = PrivacyBudget(federation_id=uuid4())

        # Query with sufficient contributors
        result = execute_private_query(
            confidences=[0.5, 0.6, 0.7, 0.8, 0.9],
            config=config,
            budget=budget,
            topic_hash="test_topic",
        )

        assert result.success is True
        assert result.epsilon_consumed == 1.0


# =============================================================================
# LOW SEVERITY TESTS
# =============================================================================


class TestConsentStoreLRU:
    """Test LRU eviction in InMemoryConsentChainStore."""

    @pytest.mark.asyncio
    async def test_chains_evicted_at_capacity(self):
        """Old chains are evicted when max capacity reached."""
        from oro_federation.consent import (
            CrossFederationConsentChain,
            InMemoryConsentChainStore,
        )

        store = InMemoryConsentChainStore(max_chains=3, max_revocations=10)

        # Add 4 chains (1 more than max)
        chains = []
        for i in range(4):
            chain = CrossFederationConsentChain(
                id=f"chain_{i}",
                original_chain_id=f"orig_{i}",
                origin_federation_id="fed_a",
                origin_gateway_id="gw_a",
            )
            chains.append(chain)
            await store.store_cross_chain(chain)

        # First chain should be evicted
        assert await store.get_cross_chain("chain_0") is None
        assert await store.get_cross_chain("chain_1") is not None
        assert await store.get_cross_chain("chain_2") is not None
        assert await store.get_cross_chain("chain_3") is not None

    @pytest.mark.asyncio
    async def test_accessed_chains_not_evicted(self):
        """Accessing a chain moves it to end of LRU queue."""
        from oro_federation.consent import (
            CrossFederationConsentChain,
            InMemoryConsentChainStore,
        )

        store = InMemoryConsentChainStore(max_chains=3, max_revocations=10)

        # Add 3 chains
        for i in range(3):
            chain = CrossFederationConsentChain(
                id=f"chain_{i}",
                original_chain_id=f"orig_{i}",
                origin_federation_id="fed_a",
                origin_gateway_id="gw_a",
            )
            await store.store_cross_chain(chain)

        # Access chain_0, making it recently used
        await store.get_cross_chain("chain_0")

        # Add another chain - should evict chain_1 (oldest non-accessed)
        chain = CrossFederationConsentChain(
            id="chain_3",
            original_chain_id="orig_3",
            origin_federation_id="fed_a",
            origin_gateway_id="gw_a",
        )
        await store.store_cross_chain(chain)

        # chain_0 should still exist (was accessed), chain_1 evicted
        assert await store.get_cross_chain("chain_0") is not None
        assert await store.get_cross_chain("chain_1") is None
