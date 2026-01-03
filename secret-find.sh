#!/bin/bash

TARGET_DIR="/root/js-analyse/wsduofen.com_20260103_143218/downloaded_js"
OUTPUT_DIR="/root/js-analyse/wsduofen.com_20260103_143218/secret-data"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "[+] Scanning $TARGET_DIR for secrets..."
echo "[+] Total JS files: $(find "$TARGET_DIR" -name "*.js" | wc -l)"
echo "[+] Output directory: $OUTPUT_DIR"
echo ""

# ============= TELEGRAM (PRIORITY) =============

echo "[*] Searching for Telegram Bot API tokens..."
result=$(grep -rEioh "[0-9]{8,10}:[A-Za-z0-9_-]{35}" "$TARGET_DIR" | sort -u)
telegram_keys=$(grep -rEioh "(telegram[_-]?(bot|api|token|key)|bot[_-]?token|TELEGRAM[_-]?TOKEN)['\"]?\s*[:=]\s*['\"]?[0-9]{8,10}:[A-Za-z0-9_-]{35}['\"]?" "$TARGET_DIR" | sort -u)
combined="${result}${telegram_keys:+$'\n'}${telegram_keys}"
[ -n "$combined" ] && echo "$combined" > "$OUTPUT_DIR/telegram_bot_tokens.txt"

echo "[*] Searching for Telegram API credentials..."
result=$(grep -rEioh "(telegram[_-]?(api[_-]?id|api[_-]?hash|phone|secret)|api[_-]?id|api[_-]?hash)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/telegram_api_credentials.txt"

# ============= WHATSAPP =============

echo "[*] Searching for WhatsApp credentials..."
result=$(grep -rEioh "(whatsapp[_-]?(token|key|secret|api|business[_-]?id)|WHATSAPP[_-]?TOKEN|wa[_-]?(token|key))['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/whatsapp_credentials.txt"

echo "[*] Searching for WhatsApp phone number IDs..."
result=$(grep -rEioh "whatsapp.*phone.*[0-9]{10,15}" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/whatsapp_phone_ids.txt"

# ============= META/FACEBOOK =============

echo "[*] Searching for Facebook/Meta tokens..."
result=$(grep -rEioh "(facebook[_-]?(token|access[_-]?token|app[_-]?secret|api[_-]?key)|fb[_-]?(token|access[_-]?token)|FACEBOOK[_-]?TOKEN)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/facebook_meta_tokens.txt"

echo "[*] Searching for Meta/Facebook App IDs..."
result=$(grep -rEioh "(app[_-]?id|facebook[_-]?app[_-]?id|fb[_-]?app[_-]?id)['\"]?\s*[:=]\s*['\"]?[0-9]{15,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/facebook_app_ids.txt"

echo "[*] Searching for Instagram credentials..."
result=$(grep -rEioh "(instagram[_-]?(token|key|secret|api)|insta[_-]?(token|key))['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/instagram_credentials.txt"

# ============= BASIC SECRETS =============

echo "[*] Searching for API keys..."
result=$(grep -rEioh "(api[_-]?(key|secret|token)|apikey|api_key)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/api_keys.txt"

echo "[*] Searching for Bearer tokens..."
result=$(grep -rEioh "bearer\s+[a-zA-Z0-9_\-\.]{20,}" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/bearer_tokens.txt"

echo "[*] Searching for AWS credentials..."
result=$(grep -rEioh "AKIA[0-9A-Z]{16}" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/aws_keys.txt"

echo "[*] Searching for private keys..."
result=$(grep -roh "BEGIN.*PRIVATE KEY" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/private_keys.txt"

echo "[*] Searching for passwords..."
result=$(grep -rEioh "(password|passwd|pwd|pass)['\"]?\s*[:=]\s*['\"]?[^'\"\\s]{6,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/passwords.txt"

echo "[*] Searching for JWT tokens..."
result=$(grep -rEioh "eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/jwt_tokens.txt"

echo "[*] Searching for database strings..."
result=$(grep -rEioh "(mongodb|mysql|postgres|redis)://[^\s'\"]+" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/database_strings.txt"

echo "[*] Searching for webhooks..."
result=$(grep -rEioh "https://hooks\.slack\.com/services/[A-Z0-9/]+" "$TARGET_DIR" | sort -u)
discord=$(grep -rEioh "https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+" "$TARGET_DIR" | sort -u)
combined="${result}${discord:+$'\n'}${discord}"
[ -n "$combined" ] && echo "$combined" > "$OUTPUT_DIR/webhooks.txt"

echo "[*] Searching for API endpoints..."
result=$(grep -rEioh "https?://[a-zA-Z0-9.-]+/api/[^\s'\"\)]*" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/api_endpoints.txt"

echo "[*] Searching for OAuth credentials..."
result=$(grep -rEioh "client[_-]?(id|secret)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/oauth_creds.txt"

echo "[*] Searching for email addresses..."
result=$(grep -rEioh "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/emails.txt"

echo "[*] Searching for generic secrets..."
result=$(grep -rEioh "(secret|token|key)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{32,})['\"]" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/generic_secrets.txt"

echo "[*] Searching for Firebase configs..."
result=$(grep -rEioh "firebase[a-zA-Z0-9_-]*\.com" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/firebase.txt"

echo "[*] Searching for Stripe keys..."
result=$(grep -rEioh "(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/stripe_keys.txt"

echo "[*] Searching for Google API keys..."
result=$(grep -rEioh "AIza[0-9A-Za-z\\-_]{35}" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/google_api_keys.txt"

echo "[*] Searching for GitHub tokens..."
result=$(grep -rEioh "gh[pousr]_[A-Za-z0-9_]{36,}" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/github_tokens.txt"

# ============= CHINESE SERVICES =============

echo "[*] Searching for Gitee tokens/keys..."
result=$(grep -rEioh "(gitee[_-]?(token|key|secret)|GITEE[_-]?(TOKEN|KEY|SECRET))['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
gitee_urls=$(grep -rEioh "https?://gitee\.com/[^\s'\"\)]*" "$TARGET_DIR" | sort -u)
combined="${result}${gitee_urls:+$'\n'}${gitee_urls}"
[ -n "$combined" ] && echo "$combined" > "$OUTPUT_DIR/gitee.txt"

echo "[*] Searching for WeChat/Tencent credentials..."
result=$(grep -rEioh "(wx[a-zA-Z0-9]{16,}|wechat[_-]?(appid|secret|key)|wxapp[_-]?(id|secret))['\"]?\s*[:=]?\s*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/wechat_tencent.txt"

echo "[*] Searching for Aliyun/Alibaba credentials..."
result=$(grep -rEioh "(LTAI[a-zA-Z0-9]{12,20}|aliyun[_-]?(key|secret|access)|alibaba[_-]?(key|secret))['\"]?\s*[:=]?\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/aliyun_alibaba.txt"

echo "[*] Searching for Tencent Cloud credentials..."
result=$(grep -rEioh "(tencent[_-]?cloud|qcloud|secretId|secretKey)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/tencent_cloud.txt"

echo "[*] Searching for Baidu API credentials..."
result=$(grep -rEioh "(baidu[_-]?(api|key|secret|token)|BAIDU[_-]?(API|KEY|SECRET))['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/baidu.txt"

echo "[*] Searching for Alipay credentials..."
result=$(grep -rEioh "(alipay[_-]?(key|secret|appid|app[_-]id)|支付宝)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/alipay.txt"

echo "[*] Searching for ByteDance/TikTok/Douyin..."
result=$(grep -rEioh "(bytedance|tiktok|douyin|aweme)[_-]?(key|secret|token|appid)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/bytedance_tiktok.txt"

echo "[*] Searching for Chinese domain APIs..."
result=$(grep -rEioh "https?://[a-zA-Z0-9.-]*\.(cn|com\.cn)/[^\s'\"\)]*" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/chinese_domains.txt"

echo "[*] Searching for Huawei Cloud credentials..."
result=$(grep -rEioh "(huawei[_-]?cloud|hwcloud)[_-]?(key|secret|access)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/huawei_cloud.txt"

echo "[*] Searching for QQ/Tencent QQ credentials..."
result=$(grep -rEioh "(qq[_-]?(key|secret|appid|token)|qqapp)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/qq_credentials.txt"

echo "[*] Searching for JD/京东 credentials..."
result=$(grep -rEioh "(jd[_-]?(key|secret|appid)|jingdong|京东)[_-]?(key|secret)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/jd_jingdong.txt"

echo "[*] Searching for Meituan/美团 credentials..."
result=$(grep -rEioh "(meituan|美团)[_-]?(key|secret|token)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/meituan.txt"

echo "[*] Searching for Weibo credentials..."
result=$(grep -rEioh "(weibo|微博)[_-]?(key|secret|token|appkey)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/weibo.txt"

echo "[*] Searching for Chinese SMS providers..."
result=$(grep -rEioh "(yunpian|阿里云短信|腾讯云短信|sms)[_-]?(key|secret|apikey)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?" "$TARGET_DIR" | sort -u)
[ -n "$result" ] && echo "$result" > "$OUTPUT_DIR/chinese_sms.txt"

# Summary
echo ""
echo "[+] Scan complete! Results saved to $OUTPUT_DIR"
echo "=========================================="
echo "[+] HIGH PRIORITY FINDINGS:"
echo "=========================================="

# Show Telegram findings first
if [ -f "$OUTPUT_DIR/telegram_bot_tokens.txt" ]; then
    count=$(wc -l < "$OUTPUT_DIR/telegram_bot_tokens.txt")
    echo "    🔴 telegram_bot_tokens.txt: $count findings"
fi

if [ -f "$OUTPUT_DIR/telegram_api_credentials.txt" ]; then
    count=$(wc -l < "$OUTPUT_DIR/telegram_api_credentials.txt")
    echo "    🔴 telegram_api_credentials.txt: $count findings"
fi

if [ -f "$OUTPUT_DIR/whatsapp_credentials.txt" ]; then
    count=$(wc -l < "$OUTPUT_DIR/whatsapp_credentials.txt")
    echo "    🟠 whatsapp_credentials.txt: $count findings"
fi

if [ -f "$OUTPUT_DIR/facebook_meta_tokens.txt" ]; then
    count=$(wc -l < "$OUTPUT_DIR/facebook_meta_tokens.txt")
    echo "    🟠 facebook_meta_tokens.txt: $count findings"
fi

echo ""
echo "[+] All Findings:"
echo "=========================================="

total_findings=0
if [ -d "$OUTPUT_DIR" ] && [ "$(ls -A "$OUTPUT_DIR" 2>/dev/null)" ]; then
    for file in "$OUTPUT_DIR"/*.txt; do
        if [ -f "$file" ]; then
            count=$(wc -l < "$file")
            echo "    $(basename "$file"): $count findings"
            total_findings=$((total_findings + count))
        fi
    done
    echo ""
    echo "[+] Total findings: $total_findings"
    echo "[+] Check files in: $OUTPUT_DIR"
else
    echo "    No secrets found!"
fi
