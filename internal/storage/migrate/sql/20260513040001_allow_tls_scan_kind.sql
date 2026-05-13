-- PR-S48-A：允许 task.kind / scan_results.kind = 'tls_scan'。
--
-- tlsx 证书探测（SPEC §2.5 资产发现矩阵证书行）；与 nuclei / subfinder
-- 同样走 ALTER CHECK 模式增量放宽。

-- +goose Up

ALTER TABLE scan_tasks DROP CONSTRAINT IF EXISTS scan_tasks_kind_valid;
ALTER TABLE scan_tasks ADD CONSTRAINT scan_tasks_kind_valid CHECK (kind IN
    ('port_scan', 'web_crawl', 'subdomain', 'fingerprint', 'vuln_scan', 'tls_scan'));

ALTER TABLE scan_results DROP CONSTRAINT IF EXISTS scan_results_kind_valid;
ALTER TABLE scan_results ADD CONSTRAINT scan_results_kind_valid CHECK (kind IN
    ('port_scan', 'web_crawl', 'subdomain', 'fingerprint', 'vuln_scan', 'tls_scan'));

-- +goose Down

ALTER TABLE scan_tasks DROP CONSTRAINT IF EXISTS scan_tasks_kind_valid;
ALTER TABLE scan_tasks ADD CONSTRAINT scan_tasks_kind_valid CHECK (kind IN
    ('port_scan', 'web_crawl', 'subdomain', 'fingerprint', 'vuln_scan'));

ALTER TABLE scan_results DROP CONSTRAINT IF EXISTS scan_results_kind_valid;
ALTER TABLE scan_results ADD CONSTRAINT scan_results_kind_valid CHECK (kind IN
    ('port_scan', 'web_crawl', 'subdomain', 'fingerprint', 'vuln_scan'));
