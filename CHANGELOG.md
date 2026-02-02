# Changelog

## 2026.01.29
- Harden session lifecycle handling and add orphan cleanup to prevent long-term growth.
- Fix memory leaks and add conditional shrinking for over-allocated hashmaps.
- Expand memory report stats and allow compile-time disabling of mem-report.
- Improve TCP client connection handling (limits and idle timeout enforcement).
