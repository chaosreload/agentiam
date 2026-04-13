#!/usr/bin/env bash
# AgentIAM Pre-Push Quality Gate
# 用法: ./scripts/pre-push-review.sh
# 每次 push 前执行，所有检查通过才能 push。

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() { echo -e "  ${GREEN}✅ $1${NC}"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}❌ $1${NC}"; FAIL=$((FAIL + 1)); }
warn() { echo -e "  ${YELLOW}⚠️  $1${NC}"; WARN=$((WARN + 1)); }

echo "═══════════════════════════════════════════"
echo " AgentIAM Pre-Push Quality Gate"
echo "═══════════════════════════════════════════"
echo ""

# ─── 1. Build ───
echo "📦 1/7 Build"
if cargo build 2>&1 | tail -1 | grep -q "Finished"; then
    pass "cargo build 成功"
else
    fail "cargo build 失败"
fi

# ─── 2. Tests ───
echo "🧪 2/7 Tests"
TEST_OUTPUT=$(cargo test 2>&1)
TEST_RESULT=$(echo "$TEST_OUTPUT" | grep "^test result:")
if echo "$TEST_RESULT" | grep -q "0 failed"; then
    TOTAL=$(echo "$TEST_RESULT" | grep -oP '\d+ passed')
    pass "cargo test — $TOTAL"
else
    fail "cargo test 有失败用例"
    echo "$TEST_OUTPUT" | grep "FAILED\|failures" | head -10
fi

# ─── 3. Clippy (zero tolerance) ───
echo "📎 3/7 Clippy"
CLIPPY_OUTPUT=$(cargo clippy -- -D warnings 2>&1)
if [ $? -eq 0 ]; then
    pass "cargo clippy — 零 warning"
else
    fail "cargo clippy 有 warning/error"
    echo "$CLIPPY_OUTPUT" | grep "warning\|error" | head -10
fi

# ─── 4. Formatting ───
echo "🎨 4/7 Formatting"
if cargo fmt --check 2>&1; then
    pass "cargo fmt — 格式规范"
else
    fail "cargo fmt — 代码格式不规范，运行 cargo fmt 修复"
fi

# ─── 5. Security: no unwrap/expect in production code ───
echo "🔒 5/7 Security — unwrap/expect in prod"
REAL_UNWRAPS=0
for f in $(find src -name '*.rs'); do
    COUNT=$(awk '/#\[cfg\(test\)\]/{exit} /\.unwrap\(\)|\.expect\(/' "$f" \
        | grep -v 'unwrap_or\|unwrap_or_default\|// safe:' | wc -l || true)
    if [ "$COUNT" -gt 0 ]; then
        echo "    ⚠ $f: $COUNT 处"
        REAL_UNWRAPS=$((REAL_UNWRAPS + COUNT))
    fi
done
if [ "$REAL_UNWRAPS" -eq 0 ]; then
    pass "生产代码零 unwrap/expect"
else
    warn "生产代码有 $REAL_UNWRAPS 处 unwrap/expect（标记 // safe: 可豁免）"
fi

# ─── 6. Security: SQL injection check ───
echo "🛡️  6/7 Security — SQL 参数化"
RAW_SQL=$(grep -rn 'format!.*SELECT\|format!.*INSERT\|format!.*UPDATE\|format!.*DELETE' src/ 2>/dev/null | wc -l || true)
if [ "$RAW_SQL" -eq 0 ]; then
    pass "无拼接 SQL（全部参数化查询）"
else
    fail "发现 $RAW_SQL 处可能的 SQL 拼接"
    grep -rn 'format!.*SELECT\|format!.*INSERT\|format!.*UPDATE\|format!.*DELETE' src/ | head -5
fi

# ─── 7. Dependencies: audit ───
echo "📋 7/7 Dependency audit"
if command -v cargo-audit &> /dev/null; then
    AUDIT_OUTPUT=$(cargo audit 2>&1)
    if echo "$AUDIT_OUTPUT" | grep -q "0 vulnerabilities"; then
        pass "cargo audit — 无已知漏洞"
    else
        warn "cargo audit 发现潜在问题"
    fi
else
    warn "cargo-audit 未安装（建议: cargo install cargo-audit）"
fi

# ─── Summary ───
echo ""
echo "═══════════════════════════════════════════"
echo -e " 结果: ${GREEN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}  ${YELLOW}${WARN} warnings${NC}"
echo "═══════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}❌ 有失败项，请修复后再 push${NC}"
    exit 1
else
    echo -e "${GREEN}✅ 全部通过，可以 push${NC}"
    exit 0
fi
