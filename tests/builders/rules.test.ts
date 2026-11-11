import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { buildRules } from "../../src/builders/rules";
import { ruleSets } from "../../src/catalog/rule-sets";

describe("buildRules", () => {
    it("未启用 quic 时插入 UDP 443 拦截规则", () => {
        const rules = buildRules({ quicEnabled: false, hasTailscale: false, adblockSource: 0 });
        assert.equal(rules[0], "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT");
    });

    it("启用 quic 时不插入拦截规则", () => {
        const rules = buildRules({ quicEnabled: true, hasTailscale: false, adblockSource: 0 });
        assert.ok(!rules.some((rule) => rule.startsWith("AND,")));
    });

    it("Tailscale 存在时生成对应分流规则", () => {
        const rules = buildRules({ quicEnabled: true, hasTailscale: true, adblockSource: 0 });
        assert.ok(rules.includes("IP-CIDR,100.64.0.0/10,Tailscale,no-resolve"));
        assert.ok(rules.includes("DOMAIN-SUFFIX,ts.net,Tailscale"));
    });

    it("Tailscale 不存在时不生成对应分流规则", () => {
        const rules = buildRules({ quicEnabled: true, hasTailscale: false, adblockSource: 0 });
        assert.ok(!rules.some((rule) => rule.includes("Tailscale")));
    });

    it("所有引用的规则集均已注册", () => {
        const rules = buildRules({ quicEnabled: true, hasTailscale: true, adblockSource: 2 });
        for (const rule of rules) {
            if (!rule.startsWith("RULE-SET,")) continue;
            const key = rule.split(",")[1];
            assert.ok(key in ruleSets, `未注册的规则集: ${key}`);
        }
    });

    it("苹果 AI 域名优先于 CDN、通用 AI 和苹果规则且全部使用独立分组", () => {
        const rules = buildRules({ quicEnabled: true, hasTailscale: false, adblockSource: 2 });
        const domains = [
            "gateway.icloud.com",
            "apple-relay.apple.com",
            "apple-relay.fastly-edge.com",
            "apple-relay.cloudflare.com",
            "guzzoni.apple.com",
            "cp4.cloudflare.com",
            "gspe1-ssl.ls.apple.com",
            "smoot.apple.com",
            "apple-relay.akamaized.net",
            "apple-relay.mask.apple-dns.net",
            "api-siri-prod.apple.com",
        ];
        const broaderRules = [
            "RULE-SET,StaticResources,静态资源",
            "RULE-SET,CDNResources,静态资源",
            "RULE-SET,AdditionalCDNResources,静态资源",
            "GEOSITE,category-ai-!cn,AI服务",
            "GEOSITE,apple,苹果服务",
        ];
        assert.equal(rules.filter((rule) => rule.endsWith(",苹果ai")).length, domains.length);
        for (const domain of domains) {
            const index = rules.indexOf(`DOMAIN-SUFFIX,${domain},苹果ai`);
            assert.ok(index >= 0, `${domain} 缺少苹果 AI 分流规则`);
            for (const broaderRule of broaderRules) {
                assert.ok(
                    index < rules.indexOf(broaderRule),
                    `${domain} 必须优先于 ${broaderRule}`
                );
            }
        }
    });

    it("保留已有 AI 域名分流且优先于通用 Google 规则", () => {
        const rules = buildRules({ quicEnabled: true, hasTailscale: false, adblockSource: 0 });
        for (const domain of [
            "openai.com",
            "chatgpt.com",
            "oaistatic.com",
            "oaiusercontent.com",
            "anthropic.com",
            "claude.ai",
            "notebooklm.google",
            "notebooklm.google.com",
            "notebooklm.googleapis.com",
        ]) {
            const index = rules.indexOf(`DOMAIN-SUFFIX,${domain},AI服务`);
            assert.ok(index >= 0);
            assert.ok(index < rules.indexOf("GEOSITE,google,谷歌服务"));
        }
    });

    it("以 MATCH 收尾", () => {
        const rules = buildRules({ quicEnabled: true, hasTailscale: false, adblockSource: 0 });
        assert.equal(rules.at(-1), "MATCH,Final");
    });

    it("adblock=0 时不包含任何广告拦截规则", () => {
        const rules = buildRules({ quicEnabled: true, hasTailscale: false, adblockSource: 0 });
        assert.ok(!rules.some((rule) => rule.includes("广告拦截")));
    });

    it("adblock>0 时统一引用 ADBlock 与 AdditionalFilter", () => {
        for (const adblockSource of [1, 2, 3] as const) {
            const rules = buildRules({ quicEnabled: true, hasTailscale: false, adblockSource });
            assert.ok(rules.includes("RULE-SET,ADBlock,广告拦截"));
            assert.ok(rules.includes("RULE-SET,AdditionalFilter,广告拦截"));
        }
    });
});
