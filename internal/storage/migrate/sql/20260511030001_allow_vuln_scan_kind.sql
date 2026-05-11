-- PR-S21-A：允许 task.kind / scan_results.kind = 'vuln_scan'。
--
-- 漏洞扫描（nuclei 插件）新增 vuln_scan 类型；老 CHECK 约束只允 4 种
-- 必须先放宽才能 INSERT。

-- +goose Up

ALTER TABLE scan_tasks DROP CONSTRAINT IF EXISTS scan_tasks_kind_valid;
ALTER TABLE scan_tasks ADD CONSTRAINT scan_tasks_kind_valid CHECK (kind IN
    ('port_scan', 'web_crawl', 'subdomain', 'fingerprint', 'vuln_scan'));

ALTER TABLE scan_results DROP CONSTRAINT IF EXISTS scan_results_kind_valid;
ALTER TABLE scan_results ADD CONSTRAINT scan_results_kind_valid CHECK (kind IN
    ('port_scan', 'web_crawl', 'subdomain', 'fingerprint', 'vuln_scan'));

-- +goose Down

ALTER TABLE scan_tasks DROP CONSTRAINT IF EXISTS scan_tasks_kind_valid;
ALTER TABLE scan_tasks ADD CONSTRAINT scan_tasks_kind_valid CHECK (kind IN
    ('port_scan', 'web_crawl', 'subdomain', 'fingerprint'));

ALTER TABLE scan_results DROP CONSTRAINT IF EXISTS scan_results_kind_valid;
ALTER TABLE scan_results ADD CONSTRAINT scan_results_kind_valid CHECK (kind IN
    ('port_scan', 'web_crawl', 'subdomain', 'fingerprint'));
